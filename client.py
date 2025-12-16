#!/usr/bin/env python3
import socket
import struct
import time
import os

SERVER_IP = "node-0"
PORT = 8080

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((SERVER_IP, PORT))

for i in range(100000):
    payload = f"hello_from_client_msg_{i}".encode()
    length = len(payload)

    # seq placeholder (8 bytes) – XDP will overwrite this
    seq_placeholder = b"\x00" * 8

    header = seq_placeholder + struct.pack("!I", length)  # !I = network-order uint32
    msg = header + payload

    sock.sendall(msg)
    time.sleep(0.05)

sock.close()
