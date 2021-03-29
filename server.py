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
from util import buildParams, decideRatio, MESSAGE_TYPE, pprintResult

parser = argparse.ArgumentParser(description='Execute output-secure LDP protocols in Server role.')
parser.add_argument('--mech', type=str, help="used mechanism [krr, oue, olh] (default: krr)", default="krr")
parser.add_argument('--cate_num', type=int, help="number of cateogories (default: 5)", default=5)
parser.add_argument('--width', type=int, help="distribution accuracy parameter (default: 100)", default=100)
parser.add_argument('--epsilon', type=float, help="privacy budget used in LDP protocol (default: 1.0)", default=1.0)
parser.add_argument('--port', type=int, help="bind port (default: 50007)", default=50007)
parser.add_argument('--address', type=str, help="bind address (default: 127.0.0.1)", default="127.0.0.1")
args = parser.parse_args()

class Verifier:
    def __init__(self, categories, d, l, n, z):
        self.categories, self.d, self.l, self.n, self.z = categories, d, l, n, z
        self.clock = time.time()
        self.result = {}
    
    def setup(self, security):
        q = number.getPrime(2 * security, Random.new().read)        
        g = number.getRandomRange(1, q-1)
        h = number.getRandomRange(1, q-1)
        
        self.q = q
        self.g = g
        self.h = h
        
        self.sigma = np.random.randint(0, self.n)
        print("sigma: ", self.sigma)
        
        self.pub_key = (q, g, h)

        a = number.getRandomRange(1, self.q-1)
        b = number.getRandomRange(1, self.q-1)
        self.a = a
        self.b = b
        
        g_a = pow(self.g, a, self.q)
        g_b = pow(self.g, b, self.q)
        g_ab = pow(self.g, a * b - self.sigma + 1, self.q)

        msg = {'type': MESSAGE_TYPE.STEP1}
        msg['g_a'] = g_a
        msg['g_b'] = g_b
        msg['g_ab'] = g_ab
        msg['pub_key'] = self.pub_key
        return msg
        
    def step2(self, msg):
        w_array, self.y_array = msg['w_array'], msg['y_array']
        self.b_array = msg['b_array']
        self.b_lin = msg['b_lin']
        secret_output = self.obliviousTransfer(w_array, self.y_array)
        ak_p1_x_array = self.P1_b(len(self.y_array))
        ak_p2_x_lin = self.P2_b()

        msg = {'type': MESSAGE_TYPE.STEP3}
        msg['ak_p1_x_array'] = ak_p1_x_array
        msg['ak_p2_x_lin'] = ak_p2_x_lin
        return msg

    def step4(self, msg):
        c_array, s_array = msg['c_array'], msg['s_array']
        p1_result = self.P1_d(c_array, s_array, self.b_array, self.y_array)
        c_lin, s_lin = msg['c_lin'], msg['s_lin']
        p2_result = self.P2_d(s_lin, c_lin, self.b_lin, self.y_array)

        if p1_result and p2_result:
            msg = {'type': MESSAGE_TYPE.OK}
        else:
            msg = {'type': MESSAGE_TYPE.NG}

        return msg

    def obliviousTransfer(self, w_array, y_array):
        v_sigma = pow(w_array[self.sigma], self.b, self.q)
        g_mu_sigma = y_array[self.sigma] * pow(pow(self.h, v_sigma, self.q), -1, self.q) % self.q
        secret_output = None
        for category in self.categories:
            if pow(self.g, self.z**category, self.q) == g_mu_sigma:
                secret_output = category
        print("secret output: ", secret_output, "g^{mu_sigma}: ", g_mu_sigma)
        return secret_output
    
    def P1_b(self, num):
        self.ak_p1_x_array = []
        for _ in range(num):
            self.ak_p1_x_array.append(number.getRandomRange(1, self.q-1))
        return self.ak_p1_x_array

    def P1_d(self, c_array, s_array, b_array, y_array):
        print("####### P1 verification #######")
        for s,c,b,y,x in zip(s_array, c_array, b_array, y_array, self.ak_p1_x_array):
            for i in self.categories:
                if pow(self.h, s[i], self.q) != b[i] * pow(y * pow(pow(self.g, self.z**i, self.q), -1, self.q) % self.q, c[i], self.q) % self.q:
                    print("False1.")
                    return False
            if x != sum(c):
                print("False2.")
                return False
        print("OK.")
        return True 
    
    def P2_b(self):
        self.ak_p2_x_lin = 0
        self.ak_p2_x_lin = number.getRandomRange(1, self.q-1)
        return self.ak_p2_x_lin
    
    def P2_d(self, s_lin, c_lin, b_lin, y_array):
        print("####### P2 verification #######")
        commitment = 1
        for y in y_array:
            commitment = commitment * y % self.q
        for category in self.categories:
            total = sum(
                [self.z**cate for cate in self.categories if cate != category]
            ) * ((self.n - self.l) // (self.d - 1)) + self.l * self.z**category
            if pow(self.h, s_lin[category], self.q) != b_lin[category] * pow(commitment * pow(pow(self.g, total, self.q), -1, self.q) % self.q, c_lin[category], self.q) % self.q:
                print("False1.")
                return False
        if self.ak_p2_x_lin != sum(c_lin):
            print("False2.")
            return False
        print("OK.")
        return True
    
    def messageHandler(self, conn, **kwargs):
        is_end = False
        msg, size = simpleRecv(conn)
        if msg == None:
            is_end = True
        elif msg['type'] == MESSAGE_TYPE.START:
            start = time.time()
            msg_to_be_send = self.setup(security=80)
            self.loggingResult('setup time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.START size [B]', size)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.STEP2:
            start = time.time()
            msg_to_be_send = self.step2(msg)
            self.loggingResult('step2 time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.STEP2 size [B]', size)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.STEP4:
            start = time.time()
            msg_to_be_send = self.step4(msg)
            self.loggingResult('step4 time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.STEP4 size [B]', size)
            simpleSend(conn, msg_to_be_send)
        else:
            assert False, "Invalid message type"
        return is_end
    
    def loggingResult(self, k, v):
        self.result[k] = v

def runServer(categories, epsilon, width, mech):
    d, l, n, z = buildParams(epsilon, width, categories)

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
            print('Discard connection.')


if __name__ == '__main__':
    categories = list(range(0,args.cate_num))
    epsilon = args.epsilon
    width = args.width
    mech = args.mech

    runServer(categories, epsilon, width, mech)
