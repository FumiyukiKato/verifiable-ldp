import pickle

BUF_SIZE=4096
SIZE_BYTE=8

def sizeToBytes(size):
    return (size).to_bytes(SIZE_BYTE, byteorder="little", signed=False)

def bytesToSize(b):
    return int.from_bytes(b, byteorder='little', signed=False)

def simpleRecv(conn):
    full_data = b''
    full_data += conn.recv(BUF_SIZE)
    if len(full_data) == 0:
        print("Lost connection")
        return None, 0

    size_bytes = full_data[:SIZE_BYTE]
    size = bytesToSize(size_bytes)

    if size > BUF_SIZE:
        repeat = (size-1) // BUF_SIZE
        for i in range(repeat):
            data = conn.recv(BUF_SIZE)
            if len(data) == 0:
                print("Lost connection")
                return None, 0
            full_data += data

    msg = pickle.loads(full_data[SIZE_BYTE:])
    return msg, size

def simpleSend(conn, msg):
    bytes_msg = pickle.dumps(msg)
    size = len(bytes_msg)
    bytes_data = sizeToBytes(size) + bytes_msg
    conn.sendall(bytes_data)