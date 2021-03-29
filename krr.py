from Crypto.Util import number
import Crypto.Random as Random
import numpy as np
import math
import time

from simpleByteProtocol import simpleRecv, simpleSend
from util import MESSAGE_TYPE

def buildKrrParams(epsilon, width, categories):
    d = len(categories)
    l, n = decideRatio(epsilon, d, width)
    assert (n-l) % (d - 1) == 0, "Invalied combination, n, l, d"
    print("n: ", n, "l: ", l, "d:", d)
    z = max([l, (n-l)//(d - 1)]) + 1
    return d, l, n, z

def decideRatio(eps, d, width):
    ratio = np.exp(eps) / ((d-1) + np.exp(eps))
    print('original p=', ratio)
    integer = int(ratio * width)
    while integer > 0:
        if (width-integer) % (d - 1) == 0:
            g = math.gcd(integer, width, (width-integer) // (d - 1))
            print('approximate p=', integer/width)
            return integer // g, width // g
        integer -= 1
    assert False, "Not found"

class KrrVerifier:
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


class KrrProver:
    def __init__(self, data, categories, d, l, n, z):
        if data in categories:
            self.data = data
        else:
            assert False, "out of categories"
        self.categories, self.d, self.l, self.n, self.z = categories, d, l, n, z
        self.clock = time.time()
        self.result = {}
        
    def setup(self):
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
        msg, size = simpleRecv(conn)
        if msg['type'] == MESSAGE_TYPE.STEP1:
            start = time.time()
            self.setPubKey(msg['pub_key'])
            msg_to_be_send = self.step1(msg)
            self.loggingResult('step1 time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.STEP1 size [B]', size)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.STEP3:
            start = time.time()
            msg_to_be_send = self.step3(msg)
            self.loggingResult('step3 time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.STEP3 size [B]', size)            
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.OK:
            print('proof is OK')
            is_end = True
        elif msg['type'] == MESSAGE_TYPE.NG:
            print('proof is NG')
            is_end = True
        else:
            assert False, "Invalid message type"
        return is_end

    def loggingResult(self, k, v):
        self.result[k] = v