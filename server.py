import argparse
import socket
import time
import numpy as np
import math
import itertools
from Crypto.Util import number
import Crypto.Random as Random
from Crypto.Hash import SHA256

from simpleByteProtocol import simpleRecv, simpleSend

parser = argparse.ArgumentParser(description='Execute output-secure LDP protocols in Server role.')
parser.add_argument('--mech', type=str, help="used mechanism [krr, oue, olh] (default: krr)", default="krr")
parser.add_argument('--cate_num', type=int, help="number of cateogories (default: 5)", default=5)
parser.add_argument('--width', type=int, help="distribution accuracy parameter (default: 100)", default=100)
parser.add_argument('--epsilon', type=float, help="privacy budget used in LDP protocol (default: 1.0)", default=1.0)
parser.add_argument('--port', type=int, help="bind port (default: 50007)", default=50007)
parser.add_argument('--address', type=str, help="bind address (default: 127.0.0.1)", default="127.0.0.1")
args = parser.parse_args()

def runServer():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.address, args.port))
        s.listen(1)
        print('listen at', args.address + ':' + str(args.port))
        while True:
            conn, addr = s.accept()
            with conn:
                msg = simpleRecv(conn)
                print(repr(msg))
        
                simpleSend(conn, b'Received!')
            print('discard connection.')


if __name__ == '__main__':
    runServer()
