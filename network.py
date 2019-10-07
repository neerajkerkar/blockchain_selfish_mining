import struct

def recv(sock, msglen):
    chunks = []
    bytes_recd = 0
    while bytes_recd < msglen:
        chunk = sock.recv(min(msglen - bytes_recd, 2048))
        if chunk == b'':
            raise RuntimeError("socket connection broken")
        chunks.append(chunk)
        bytes_recd = bytes_recd + len(chunk)
    return b''.join(chunks)

def get_msg(sock):
    length = struct.unpack('>i', recv(sock, 4))[0]
    return recv(sock, length)

def send(sock, msg):
    totalsent = 0
    while totalsent < len(msg):
        sent = sock.send(msg[totalsent:])
        if sent == 0:
            raise RuntimeError("socket connection broken")
        totalsent = totalsent + sent

def send_msg(sock, msg):
    length = struct.pack('>i', len(msg))
    sock.sendall(length)
    sock.sendall(msg)