import argparse
import socket
import time

from simpleByteProtocol import simpleRecv, simpleSend
from util import pprintResult, saveJsonResult
from krr import KrrVerifier, buildKrrParams
from oue import OueVerifier, buildOueParams
from olh import OlhVerifier, buildOlhParams
from normal import NormalVerifier

parser = argparse.ArgumentParser(description='Execute output-secure LDP protocols in Server role.')
parser.add_argument('--mech', type=str, help="used mechanism [krr, oue, olh] (default: krr)", default="krr")
parser.add_argument('--cate_num', type=int, help="number of cateogories (default: 5)", default=5)
parser.add_argument('--width', type=int, help="distribution accuracy parameter (default: 100)", default=100)
parser.add_argument('--epsilon', type=float, help="privacy budget used in LDP protocol (default: 1.0)", default=1.0)
parser.add_argument('--port', type=int, help="bind port (default: 50007)", default=50007)
parser.add_argument('--address', type=str, help="bind address (default: 127.0.0.1)", default="127.0.0.1")
parser.add_argument('--g', type=int, help="output space size (g < cate_num) when mech=olh (default: 5)", default=5)
args = parser.parse_args()

def runServer(categories, epsilon, width, Verifier, d, l, n, z):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((args.address, args.port))
        s.listen(1)
        print('listen at', args.address + ':' + str(args.port))
        while True:
            print('Start accept...')
            conn, addr = s.accept()
            with conn:
                verifier = Verifier(categories, d, l, n, z)
                while True:
                    if verifier.messageHandler(conn):
                        break
                verifier.loggingResult('overall time', time.time() - verifier.clock)
                pprintResult(verifier.result)
            print('Finish protocol.')
            return verifier.result


if __name__ == '__main__':
    categories = list(range(0,args.cate_num))
    epsilon = args.epsilon
    width = args.width
    mech = args.mech
    if mech == "krr":
        Verifier = KrrVerifier
        d, l, n, z = buildKrrParams(epsilon, width, categories)
    elif mech == "oue":
        Verifier = OueVerifier
        d, l, n = buildOueParams(epsilon, width, categories)
        z = 0
    elif mech == "olh":
        Verifier = OlhVerifier
        d, l, n, z = buildOlhParams(epsilon, width, args.g)
    elif mech == 'normal':
        Verifier = NormalVerifier
        d, l, n, z = 0, 0, 0, 0
    else:
        assert False, "Invalid parameter mech"
    
    result = runServer(categories, epsilon, width, Verifier, d, l, n, z)
    params = ['verifier', args.cate_num, epsilon, width, mech]
    if mech == "olh":
        params = ['verifier', args.cate_num, epsilon, width, args.g, mech]

    saveJsonResult(result, dir_name='result', params=params)
