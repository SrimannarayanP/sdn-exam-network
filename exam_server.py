# exam_server.py


"""
    - Accepts concurrent student conns over TCP sockets (port 9999).
    - Allows up to 3 auth attempts per conn so legit students who mistype their ID are not locked out.
    - If a client fails all 3 attempts (unauth-ed/brute-force), sends an explicit 'SDN_BLOCK_HOST' TCP payload that the SDN switch ctrller intercepts to drop future pkts
        from that IP at Layer 3.
    - Enforces exam timer, serves Qs & grades submissions.
"""


from protocol import recv_json, send_json

import argparse, socket, threading, time


QUESTIONS = [
    {
        'qid': 1,
        'text': "1 + 1",
        'opts': {'A': '1', 'B': '2', 'C': '3', 'D': '4'},
        'ans': 'B' 
    },
    {
        'qid': 2,
        'text': "2 + 3",
        'opts': {'A': '5', 'B': '6', 'C': '7', 'D': '8'},
        'ans': 'A' 
    },
    {
        'qid': 3,
        'text': "1 + 3",
        'opts': {'A': '4', 'B': '5', 'C': '6', 'D': '7'},
        'ans': 'A' 
    },
    {
        'qid': 4,
        'text': "3 + 5",
        'opts': {'A': '8', 'B': '9', 'C': '10', 'D': '11'},
        'ans': 'A'
    }
]

AUTHORIZED_STUDENTS = {'PES1', 'PES2', 'PES3', 'PES4', 'PES5'}

MAX_AUTH_ATTEMPTS = 3


class OnlineExamServer:

    def __init__(self, host, port, duration):
        self.host = host
        self.port = port
        self.duration = duration
        self.exam_start_time = time.time()
        self.exam_deadline = self.exam_start_time + self.duration
        self.results_lock = threading.Lock()
        self.scores = {}

    def remaining_time(self):

        return max(0.0, self.exam_deadline - time.time())

    def handle_student(self, conn: socket.socket, addr):
        client_ip, client_port = addr

        student_id = 'UNKNOWN'

        try:
            # Authentication loop (Up to 3 retries so typos don't block legit students)
            authenticated = False

            for attempt in range(1, MAX_AUTH_ATTEMPTS + 1):
                req = recv_json(conn)
                if not req or req.get('type') != 'AUTH': return

                student_id = req.get('student_id', '').strip()
                if student_id in AUTHORIZED_STUDENTS:
                    authenticated = True

                    break

                attempts_left = MAX_AUTH_ATTEMPTS - attempt
                if attempts_left > 0:
                    print(f"[AUTH-WARN] Invalid ID '{student_id}' from {client_ip}. Attempts left: {attempts_left}")

                    send_json(conn, {'type': 'AUTH_RETRY', 'attempts_left': attempts_left, 'reason': f"Invalid ID '{student_id}'. Please retry ({attempts_left} attempts left)."})
                else:
                    print(f"[SECURITY] {client_ip} failed {MAX_AUTH_ATTEMPTS} auth attempts ('{student_id}'). Triggering SDN Switch Block...")

                    send_json(conn, {'type': 'SDN_BLOCK_HOST', 'reason': "3 failed auth attempts. Your IP has been blocked at the SDN switch."})

                    return

            if not authenticated: return

            # Authorized. Send AUTH_OK (Ctrller intercepts this to install Priority 100 rule).
            send_json(conn, {'type': 'AUTH_OK', 'total_Qs': len(QUESTIONS), 'remaining_sec': round(self.remaining_time(), 2)})

            print(f"[AUTH-OK] Student {student_id} ({client_ip}:{client_port}) auth-ed. Time left: {self.remaining_time():.1f}s")

            score = 0

            # Q delivery & ans submission.
            while True:
                msg = recv_json(conn)
                if not msg: break

                msg_type = msg.get('type')
                if msg_type == 'GET_QUESTION':
                    q_idx = msg.get('index', 0)

                    rem = self.remaining_time()
                    if rem <= 0:
                        send_json(conn, {'type': 'TIME_UP', 'msg': "Exam timer expired!"})

                        break
                    
                    if 0 <= q_idx < len(QUESTIONS):
                        q = QUESTIONS[q_idx]

                        send_json(conn, {'type': 'QUESTION', 'qid': q['qid'], 'text': q['text'], 'opts': q['opts'], 'remaining_sec': round(rem, 2)})
                elif msg_type == 'SUBMIT_ANS':
                    rem = self.remaining_time()
                    if rem <= 0:
                        send_json(conn, {'type': 'TIME_UP', 'accepted': False, 'remaining_sec': 0.0})

                        break

                    q_idx = msg.get('index', 0)
                    ans = msg.get('ans', '').upper()

                    if (0 <= q_idx < len(QUESTIONS)) and (QUESTIONS[q_idx]['ans'] == ans):
                        score += 1

                    send_json(conn, {'type': 'ACK_ANS', 'qid': QUESTIONS[q_idx]['qid'], 'accepted': True, 'remaining_sec': round(rem, 2)})
                elif msg_type == 'FINISH_EXAM': break

            with self.results_lock:
                self.scores[student_id] = {'score': score, 'total': len(QUESTIONS), 'ip': client_ip}

            send_json(conn, {'type': 'RESULT', 'student_id': student_id, 'score': score, 'total': len(QUESTIONS), 'remaining_sec': round(self.remaining_time(), 2)})

            print(f"[COMPLETED] Student {student_id} finished. Score: {score}/{len(QUESTIONS)}")
        except Exception as e:
            print(f"[ERR] Session err with {student_id} ({client_ip}): {e}")
        finally:
            conn.close()

    def serve_forever(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((self.host, self.port))
        srv.listen(32)

        print(f"[EXAM SERVER] Pure-TCP server listening on {self.host}:{self.port} (Timer: {self.duration}s)")

        try:
            while True:
                conn, addr = srv.accept()

                t = threading.Thread(target = self.handle_student, args = (conn, addr), daemon = True)
                t.start()
        except KeyboardInterrupt:
            print("\n[EXAM SERVER] Shutting Down. Final Scoreboard: ", self.scores)
        finally:
            srv.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', default = '0.0.0.0')
    parser.add_argument('--port', type = int, default = 9999)
    parser.add_argument('--duration', type = int, default = 60)
    args = parser.parse_args()

    server = OnlineExamServer(args.host, args.port, args.duration)
    server.serve_forever()