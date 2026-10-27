# protocol.py


"""
    Low-level TCP socket framing protocol. Prefixes every UTF-8 JSON payload with a 4B unsigned big-endian length header.
"""


from typing import Any, Dict, Optional

import json, socket, struct


HEADER_FORMAT = '!I'
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def send_json(sock: socket.socket, payload):
    raw_Bs = json.dumps(payload).encode('utf-8') # raw_bytes
    header = struct.pack(HEADER_FORMAT, len(raw_Bs))
    sock.sendall(header + raw_Bs)

def recv_json(sock: socket.socket):
    header_Bs = _recv_exact(sock, HEADER_SIZE)
    if not header_Bs: return None

    (msg_len,) = struct.unpack(HEADER_FORMAT, header_Bs)

    payload_Bs = _recv_exact(sock, msg_len)
    if not payload_Bs: return None

    return json.loads(payload_Bs.decode('utf-8'))

def _recv_exact(sock: socket.socket, num_Bs):
    buf = bytearray()

    while len(buf) < num_Bs:
        chunk = sock.recv(num_Bs - len(buf))
        if not chunk: return None

        buf.extend(chunk)

    return bytes(buf)