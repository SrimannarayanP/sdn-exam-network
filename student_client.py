# student_client.py


"""
    - Conns to the exam server (port 9999) over a low-level TCP socket.
    - Auths (upto 3 attempts in case of any typos; if a rogue user fails all 3 attempts, they receive 'SDN_BLOCK_HOST' & gets blocked at the OpenFlow switch.)
    - Retrieves Qs, simulates student thinking time & submits ans before the exam timer expires.
    - Measures per-msg Round-Trip Time (RTT in ms) for SDN performance eval. 
"""


from protocol import recv_json, send_json

import argparse, json, socket, time


SAMPLE_ANSWERS = ['A', 'A', 'A', 'A']

MAX_AUTH_ATTEMPTS = 3


def run_student(student_id, server_ip, server_port, think_time, log_file, simulate_typo):
    rtts_ms = []
    
    start_wall = time.perf_counter()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10.0)

    try:
        t0 = time.perf_counter()

        sock.connect((server_ip, server_port))

        # Auth handshake (Upto 3 attempts)
        auth_resp = None

        for attempt in range(1, MAX_AUTH_ATTEMPTS + 1):
            # If --typo-first is enabled, send a mistyped ID on attempt 1 & then the real ID on attempt 2.
            id_to_send = f'{student_id}_TYPO' if (simulate_typo and attempt == 1) else student_id

            send_json(sock, {'type': 'AUTH', 'student_id': id_to_send})
            
            auth_resp = recv_json(sock)
            if not auth_resp: break

            resp_type = auth_resp.get('type')
            if resp_type == 'AUTH_OK': break
            elif resp_type == 'AUTH_RETRY':
                print(f"[{student_id}] Attempt {attempt}/3 warning: {auth_resp.get('reason')}")
            elif resp_type == 'SDN_BLOCK_HOST':
                print(f"[{student_id}] BLOCKED BY SDN CTRLLER: {auth_resp.get('reason')}")

                break

        rtts_ms.append((time.perf_counter() - t0)*1000.0)

        if not auth_resp or auth_resp.get('type') != 'AUTH_OK':
            # Verify that pkts from a blocked rogue host are dropped by the switch. 
            if auth_resp and auth_resp.get('type') == 'SDN_BLOCK_HOST':
                try:
                    verify_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    verify_sock.settimeout(1.5)
                    verify_sock.connect((server_ip, server_port))
                    verify_sock.close()
                except socket.timeout:
                    print(f"[{student_id}] Confirmed: Switch s1 is now dropping all TCP SYN pkts from this IP.")
                except Exception:
                    pass

            return
        
        total_q = auth_resp['total_Qs']

        print(f"[{student_id}] Auth-ed. {total_q} questions, {auth_resp['remaining_sec']}s remaining.")

        # Q delivery & ans submission
        for i in range(total_q):
            t_q = time.perf_counter()

            send_json(sock, {'type': 'GET_QUESTION', 'index': i})

            q_resp = recv_json(sock)

            q_rtt = (time.perf_counter() - t_q)*1000.0
            rtts_ms.append(q_rtt)

            if not q_resp or q_resp.get('type') == 'TIME_UP':
                print(f"[{student_id}] Exam timer expired while fetching Q{i + 1}")

                break

            # Simulate student reading/solving the Q
            time.sleep(think_time)

            # Submit ans for Q i
            chosen_ans = SAMPLE_ANSWERS[i%len(SAMPLE_ANSWERS)]

            t_a = time.perf_counter()

            send_json(sock, {'type': 'SUBMIT_ANS', 'index': i, 'ans': chosen_ans})

            ack = recv_json(sock)

            a_rtt = (time.perf_counter() - t_a)*1000.0
            rtts_ms.append(a_rtt)

            if not ack or ack.get('type') == 'TIME_UP':
                print(f"[{student_id}] Exam timer expired while submitting Q{i + 1}")

                break

            print(f"[{student_id}] Q{i + 1} submitted (Ans: {chosen_ans}) | Q_RTT: {q_rtt:.2f}ms, ACK_RTT: {a_rtt:.2f}ms | Timer: {ack.get('remaining_sec')}s")

        # Req final exam score
        send_json(sock, {'type': 'FINISH_EXAM'})

        result = recv_json(sock)

        total_time_s = time.perf_counter() - start_wall

        avg_rtt = sum(rtts_ms)/len(rtts_ms) if rtts_ms else 0.0

        summary = {
            'student_id': student_id,
            'score': result.get('score', 0) if result else 0,
            'total': result.get('total', total_q) if result else total_q,
            'avg_rtt_ms': round(avg_rtt, 2),
            'max_rtt_ms': round(max(rtts_ms), 2) if rtts_ms else 0.0,
            'completion_time_s': round(total_time_s, 2)
        }

        print(f"[{student_id}] FINAL RESULT: {summary}")

        if log_file:
            with open(log_file, 'a', encoding = 'utf-8') as f:
                f.write(json.dumps(summary) + '\n')
    except Exception as e:
        print(f"[{student_id}] Socket Err/Timeout: {e}")
    finally:
        sock.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', required = True, help = "Student ID (e.g., PES1,..., PES5 or HACKER99)")
    parser.add_argument('--server', default = '10.0.0.100', help = "Exam Server IP")
    parser.add_argument('--port', type = int, default = 9999)
    parser.add_argument('--think', type = float, default = 0.5, help = "Simulated time spent per question (sec)")
    parser.add_argument('--log', default = '', help = "Optional JSONL output file for metrics")
    parser.add_argument('--typo-first', action = 'store_true', help = "Simulate a 1st-attempt typo that recovers on attempt 2")
    args = parser.parse_args()

    run_student(args.id, args.server, args.port, args.think, args.log, args.typo_first)