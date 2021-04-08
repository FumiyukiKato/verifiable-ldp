import argparse
import socket
import time

from simpleByteProtocol import simpleRecv, simpleSend
from util import MESSAGE_TYPE, pprintResult, saveJsonResult
from krr import KrrProver, buildKrrParams
from oue import OueProver, buildOueParams
from olh import OlhProver, buildOlhParams
from normal import NormalProver

parser = argparse.ArgumentParser(description='Execute output-secure LDP protocols in Server role.')
parser.add_argument('--mech', type=str, help="used mechanism [krr, oue, olh] (default: krr)", default="krr")
parser.add_argument('--cate_num', type=int, help="number of cateogories (default: 5)", default=5)
parser.add_argument('--width', type=int, help="distribution accuracy parameter (default: 100)", default=100)
parser.add_argument('--epsilon', type=float, help="privacy budget used in LDP protocol (default: 1.0)", default=1.0)
parser.add_argument('--port', type=int, help="bind port (default: 50007)", default=50007)
parser.add_argument('--address', type=str, help="bind address (default: 127.0.0.1)", default="127.0.0.1")
parser.add_argument('--sensitive_value', type=int, help="sensitive value (default: 0)", default=0)
parser.add_argument('--g', type=int, help="output space size (g < cate_num) when mech=olh (default: 5)", default=5)
args = parser.parse_args()


def runClient(categories, epsilon, secret_input, width, Prover, d, l, n, z):
    prover = Prover(secret_input, categories, d, l, n, z)
    prover.setup()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.address, args.port))
        prover.clock = time.time()
        start_msg = {'type': MESSAGE_TYPE.START}
        simpleSend(s, start_msg)
        while True:
            if prover.messageHandler(s):
                break
        s.close()
    prover.loggingResult('overall time', time.time() - prover.clock)
    pprintResult(prover.result)
    return prover.result


if __name__ == '__main__':
    categories = list(range(0,args.cate_num))
    epsilon = args.epsilon
    secret_input = args.sensitive_value
    width = args.width
    mech = args.mech
    if mech == "krr":
        Prover = KrrProver
        d, l, n, z = buildKrrParams(epsilon, width, categories)
    elif mech == "oue":
        Prover = OueProver
        d, l, n = buildOueParams(epsilon, width, categories)
        z = 0
    elif mech == "olh":
        Prover = OlhProver
        d, l, n, z = buildOlhParams(epsilon, width, args.g)
    elif mech == 'normal':
        Prover = NormalProver
        d, l, n, z = 0, 0, 0, 0
    else:
        assert False, "Invalid parameter mech"

    result = runClient(categories, epsilon, secret_input, width, Prover, d, l, n, z)
    params = ['prover', args.cate_num, epsilon, secret_input, width, mech]
    if mech == "olh":
        params = ['prover', args.cate_num, epsilon, secret_input, width, args.g, mech]

    saveJsonResult(result, dir_name='result', params=params)