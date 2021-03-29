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
from util import buildParams, decideRatio, MESSAGE_TYPE

parser = argparse.ArgumentParser(description='Execute output-secure LDP protocols in Server role.')
parser.add_argument('--mech', type=str, help="used mechanism [krr, oue, olh] (default: krr)", default="krr")
parser.add_argument('--cate_num', type=int, help="number of cateogories (default: 5)", default=5)
parser.add_argument('--width', type=int, help="distribution accuracy parameter (default: 100)", default=100)
parser.add_argument('--epsilon', type=float, help="privacy budget used in LDP protocol (default: 1.0)", default=1.0)
parser.add_argument('--port', type=int, help="bind port (default: 50007)", default=50007)
parser.add_argument('--address', type=str, help="bind address (default: 127.0.0.1)", default="127.0.0.1")
parser.add_argument('--sensitive_value', type=int, help="sensitive value (default: 0)", default=0)
args = parser.parse_args()

class Prover:
    def __init__(self, data, categories, d, l, n, z):
        if data in categories:
            self.data = data
        else:
            assert False, "out of categories"
        self.categories, self.d, self.l, self.n, self.z = categories, d, l, n, z
        
    def setup(self):
        print('Prover setup')
        t = self.data
        print("secret input: ", t)
        mu_array = []
        mu_array = [t]*self.l
        for category in self.categories:
            if category != t:
                mu_array = mu_array + ([category] * ((self.n - self.l) // (self.d - 1)))
        mu_array = np.random.permutation(mu_array).tolist()
        self.mu_array = mu_array
        
    def setPubKey(self, pub_key):
        self.pub_key = pub_key
    
    def step1(self, msg):
        print('step1')
        g_a, g_b, g_ab = msg['g_a'], msg['g_b'], msg['g_ab']
        w_array, y_array = self.encryption(g_a, g_b, g_ab)
        b_array = self.P1_a()
        b_lin = self.P2_a()

        msg = {'type': MESSAGE_TYPE.STEP2}
        msg['w_array'] = w_array
        msg['y_array'] = y_array
        msg['b_array'] = b_array
        msg['b_lin'] = b_lin
        return msg

    def step3(self, msg):
        print('step3')
        ak_p1_x_array = msg['ak_p1_x_array']
        c_array, s_array = self.P1_c(ak_p1_x_array)
        ak_p2_x_lin = msg['ak_p2_x_lin']
        c_lin, s_lin = self.P2_c(ak_p2_x_lin)

        msg = {'type': MESSAGE_TYPE.STEP4}
        msg['c_array'] = c_array
        msg['s_array'] = s_array
        msg['c_lin'] = c_lin
        msg['s_lin'] = s_lin
        return msg        
        
    def encryption(self, g_a, g_b, g_ab):
        q, g, h = self.pub_key
        w_array = []
        y_array = []
        v_array = []
        
        for i in range(0, self.n):
            r = number.getRandomRange(1, q-1)
            s = number.getRandomRange(1, q-1)
            w = pow(g, r, q) * pow(g_a, s, q) % q
            v = pow(g_b, r, q) * pow(g_ab * pow(g, i-1, q) % q, s, q) % q
            y = pow(g, self.z**self.mu_array[i], q) * pow(h, v, q) % q
            w_array.append(w)
            y_array.append(y)
            v_array.append(v)

        self.w_array = w_array
        self.y_array = y_array
        self.v_array = v_array

        return w_array, y_array
    
    def P1_a(self):
        q, g, h = self.pub_key
        b_array = []
        c_array = []
        s_array = []
        random_w_array = []
        for y, mu in zip(self.y_array, self.mu_array):
            random_w = number.getRandomRange(1, q-1)
            c = [0] * self.d
            s = [0] * self.d
            b = [0] * self.d
            for category in self.categories:
                if category != mu:
                    c_i = number.getRandomRange(1, q-1)
                    s_i = number.getRandomRange(1, q-1)
                    c[category] = c_i
                    s[category] = s_i
                    g_i_inv = pow(pow(g, self.z**category, q), -1, q)
                    deno = pow(y * g_i_inv % q, c_i, q)
                    b_i = pow(h, s_i, q) * pow(deno, -1, q) % q
                    b[category] = b_i
                else:
                    b_i = pow(h, random_w, q)
                    b[category] = b_i
            random_w_array.append(random_w)
            b_array.append(b)
            c_array.append(c)
            s_array.append(s)

        self.b_array = b_array
        self.s_array = s_array
        self.c_array = c_array
        self.random_w_array = random_w_array
        
        return b_array
    
    def P1_c(self, ak_p1_x_array):
        q, g, h = self.pub_key
        for x,c,s,mu,v,random_w in zip(ak_p1_x_array, self.c_array, self.s_array, self.mu_array, self.v_array, self.random_w_array):
            for category in self.categories:
                if category == mu:
                    c[mu] = x - sum(c)
                    s[mu] = v * c[mu] + random_w

        return self.c_array, self.s_array
    
    def P2_a(self):
        q, g, h = self.pub_key
        b_lin = [0] * self.d
        c_lin = [0] * self.d
        s_lin = [0] * self.d
        random_w = number.getRandomRange(1, q-1)
        for category in self.categories:
            if category != self.data:
                total = sum(
                    [self.z**cate for cate in self.categories if cate != category]
                ) * ((self.n - self.l) // (self.d - 1)) + self.l * self.z**category
                c_i = number.getRandomRange(1, q-1)
                s_i = number.getRandomRange(1, q-1)
                c_lin[category] = c_i
                s_lin[category] = s_i
                g_i_inv = pow(pow(g, total, q), -1, q)
                commitment = 1
                for y in self.y_array:
                    commitment = commitment * y % q
                deno = pow(commitment * g_i_inv % q, c_i, q)
                b_i = pow(h, s_i, q) * pow(deno, -1, q) % q
                b_lin[category] = b_i
            else:
                b_i = pow(h, random_w, q)
                b_lin[category] = b_i

        self.b_lin = b_lin
        self.s_lin = s_lin
        self.c_lin = c_lin
        self.random_w_lin = random_w
        return b_lin

    def P2_c(self, ak_p2_x_lin):
        q, g, h = self.pub_key
        for category in self.categories:
            if category == self.data:
                self.c_lin[self.data] = ak_p2_x_lin - sum(self.c_lin)
                v_sum = 0
                for v in self.v_array:
                    v_sum += v
                self.s_lin[self.data] = v_sum * self.c_lin[self.data] + self.random_w_lin
        return self.c_lin, self.s_lin

    def messageHandler(self, conn):
        is_end = False
        msg = simpleRecv(conn)
        if msg['type'] == MESSAGE_TYPE.STEP1:
            self.setPubKey(msg['pub_key'])
            msg_to_be_send = self.step1(msg)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.STEP3:
            msg_to_be_send = self.step3(msg)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.OK:
            print('OK')
            is_end = True
        elif msg['type'] == MESSAGE_TYPE.NG:
            print('NG')
            is_end = True
        else:
            assert False, "Invalid message type"
        return is_end


def runClient(categories, epsilon, secret_input, width, mech):
    d, l, n, z = buildParams(epsilon, width, categories)

    prover = Prover(secret_input, categories, d, l, n, z)
    prover.setup()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.address, args.port))
        start_msg = {'type': MESSAGE_TYPE.START}
        simpleSend(s, start_msg)
        while True:
            if prover.messageHandler(s):
                break
        s.close()
        print('close')


if __name__ == '__main__':
    categories = list(range(0,args.cate_num))
    epsilon = args.epsilon
    secret_input = args.sensitive_value
    width = args.width
    mech = args.mech

    runClient(categories, epsilon, secret_input, width, mech)