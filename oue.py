from Crypto.Util import number
import Crypto.Random as Random
import numpy as np
import math
import time
import pickle

from simpleByteProtocol import simpleRecv, simpleSend
from util import MESSAGE_TYPE, pprintResult, saveJsonResult

def buildOueParams(epsilon, width, categories):
    d = len(categories)
    l = decideRatio(epsilon, d, width)
    n = width
    # print("n:", n, "l:", l, "d:", d)
    return d, l, n

def decideRatio(eps, d, width):
    """ Return:
            int: number of zero 
    """
    if width % 2 != 0:
        assert False, "width must be even"
    ratio = 1 / (1 + np.exp(eps))
    # print('original q=', ratio)
    # print('approximate q=', math.ceil(ratio * width)/100)
    return int(ratio * width)

class OueVerifier:
    def __init__(self, categories, d, l, n, z):
        self.categories, self.d, self.l, self.n = categories, d, l, n
        self.clock = time.time()
        self.result = {}
    
    def setup(self, security):
        q = number.getPrime(2 * security, Random.new().read)        
        g = number.getRandomRange(1, q-1)
        h = number.getRandomRange(1, q-1)
        
        self.q = q
        self.g = g
        self.h = h
        
        self.sigma_array = np.random.randint(0, self.n, self.d).tolist()
        print("sigma: ", self.sigma_array)
        
        self.pub_key = (q, g, h)

        a_array = [number.getRandomRange(1, self.q-1) for _ in range(self.d)]
        b_array = [number.getRandomRange(1, self.q-1) for _ in range(self.d)]
        self.a_array = a_array
        self.b_array = b_array
        
        g_a_array = [pow(self.g, a, self.q) for a in a_array]
        g_b_array = [pow(self.g, b, self.q) for b in b_array]
        g_ab_array = [pow(self.g, a * b - sigma + 1, self.q) for sigma, a, b in zip(self.sigma_array, a_array, b_array)]

        msg = {'type': MESSAGE_TYPE.STEP1}
        msg['g_a_array'] = g_a_array
        msg['g_b_array'] = g_b_array
        msg['g_ab_array'] = g_ab_array
        msg['pub_key'] = self.pub_key
        return msg
        
    def step2(self, msg):
        vec_w_array, self.vec_y_array = msg['vec_w_array'], msg['vec_y_array']
        self.vec_b_array = msg['vec_b_array']
        self.vec_b_lin = msg['vec_b_lin']
        secret_output = self.obliviousTransfer(vec_w_array, self.vec_y_array)
        vec_ak_p1_x_array = self.P1_b(self.n, self.d)
        vec_ak_p2_x_lin = self.P2_b(self.d)

        msg = {'type': MESSAGE_TYPE.STEP3}
        msg['vec_ak_p1_x_array'] = vec_ak_p1_x_array
        msg['vec_ak_p2_x_lin'] = vec_ak_p2_x_lin
        return msg

    def step4(self, msg):
        vec_c_array, vec_s_array = msg['vec_c_array'], msg['vec_s_array']
        p1_result = self.P1_d(vec_c_array, vec_s_array, self.vec_b_array, self.vec_y_array)
        vec_c_lin, vec_s_lin = msg['vec_c_lin'], msg['vec_s_lin']
        p2_result = self.P2_d(vec_c_lin, vec_s_lin, self.vec_b_lin, self.vec_y_array)
        v_s = msg['v_s']
        p3_result = self.p3_b(self.vec_y_array, v_s)

        if p1_result and p2_result and p3_result:
            msg = {'type': MESSAGE_TYPE.OK}
        else:
            msg = {'type': MESSAGE_TYPE.NG}

        return msg

    def obliviousTransfer(self, vec_w_array, vec_y_array):
        result_array = []
        for b, sigma, w_array, y_array in zip(self.b_array, self.sigma_array, vec_w_array, vec_y_array):
            v_sigma = pow(w_array[sigma], b, self.q)
            g_mu_sigma = y_array[sigma] * pow(pow(self.h, v_sigma, self.q), -1, self.q) % self.q
            for bit in [0, 1]:
                if pow(self.g, bit, self.q) == g_mu_sigma:
                    result_array.append(bit)
        assert len(result_array) == self.d, "invalid verification"
                    
        print("secret output: ", result_array)
        return result_array
    
    def P1_b(self, n, d):
        self.vec_ak_p1_x_array = []
        for _ in range(d):
            self.vec_ak_p1_x_array.append(
                [number.getRandomRange(1, self.q-1) for _ in range(n)]
            )
        return self.vec_ak_p1_x_array

    def P1_d(self, vec_c_array, vec_s_array, vec_b_array, vec_y_array):
        print("####### P1 verification #######")
        for c_array,s_array,b_array,y_array,ak_p1_x_array in zip(
            vec_c_array, vec_s_array, vec_b_array, vec_y_array, self.vec_ak_p1_x_array
        ):
            for s,c,b,y,x in zip(s_array, c_array, b_array, y_array, ak_p1_x_array):
                for i in [0, 1]:
                    if pow(self.h, s[i], self.q) != b[i] * pow(y * pow(pow(self.g, i, self.q), -1, self.q) % self.q, c[i], self.q) % self.q:
                        print("NG.")
                        return False
                if x != sum(c):
                    print("NG.")
                    return False
        print("OK.")
        return True 
    
    def P2_b(self, d):
        self.vec_ak_p2_x_lin = []
        for i in range(d):
            self.vec_ak_p2_x_lin.append(number.getRandomRange(1, self.q-1))
        return self.vec_ak_p2_x_lin
    
    def P2_d(self, vec_c_lin, vec_s_lin, vec_b_lin, vec_y_array):
        print("####### P2 verification #######")
        for category, c_lin, s_lin, b_lin, y_array, ak_p2_x_lin in zip(
            self.categories, vec_c_lin, vec_s_lin, vec_b_lin, vec_y_array, self.vec_ak_p2_x_lin
        ):
            commitment = 1
            for y in y_array:
                commitment = commitment * y % self.q
            for c, s, b, summation in zip(c_lin, s_lin, b_lin, [self.n // 2, self.l]):
                if pow(self.h, s, self.q) != b * pow(commitment * pow(pow(self.g, summation, self.q), -1, self.q) % self.q, c, self.q) % self.q:
                    print("NG.")
                    return False
            if ak_p2_x_lin != sum(c_lin):
                print("NG.")
                return False
        print("OK.")
        return True
    
    def p3_b(self, vec_y_array, v_s):
        print("####### P3 verification #######")
        prd_y = 1
        for y_array in vec_y_array:
            for y in y_array:
                prd_y = prd_y * y % self.q
        if prd_y != (pow(self.g, self.n//2 + (self.d-1)*self.l, self.q) * pow(self.h, v_s, self.q) % self.q):
            print("NG.")
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


class OueProver:
    def __init__(self, data, categories, d, l, n, z):
        if data in categories:
            self.data = data
        else:
            assert False, "out of categories"
        self.categories, self.d, self.l, self.n = categories, d, l, n
        self.clock = time.time()
        self.result = {}
        
    def setup(self):
        t = self.data
        print("secret input: ", t)
        vec_mu_array = [[]]*self.d
        for category in self.categories:
            if category == t:
                bit_array = [0]*(self.n // 2) + [1]*(self.n // 2)
            else:
                bit_array = [0]*(self.n - self.l) + [1]*self.l
            bit_array = np.random.permutation(bit_array).tolist()
            vec_mu_array[category] = bit_array
        self.vec_mu_array = vec_mu_array
        
    def setPubKey(self, pub_key):
        self.pub_key = pub_key
    
    def step1(self, msg):
        g_a_array, g_b_array, g_ab_array = msg['g_a_array'], msg['g_b_array'], msg['g_ab_array']
        vec_w_array, vec_y_array = self.encryption(g_a_array, g_b_array, g_ab_array)
        vec_b_array = self.P1_a()
        vec_b_lin = self.P2_a()

        msg = {'type': MESSAGE_TYPE.STEP2}
        msg['vec_w_array'] = vec_w_array
        msg['vec_y_array'] = vec_y_array
        msg['vec_b_array'] = vec_b_array
        msg['vec_b_lin'] = vec_b_lin
        return msg

    def step3(self, msg):
        vec_ak_p1_x_array = msg['vec_ak_p1_x_array']
        vec_c_array, vec_s_array = self.P1_c(vec_ak_p1_x_array)
        vec_ak_p2_x_lin = msg['vec_ak_p2_x_lin']
        vec_c_lin, vec_s_lin = self.P2_c(vec_ak_p2_x_lin)
        v_s = self.p3_a()

        msg = {'type': MESSAGE_TYPE.STEP4}
        msg['vec_c_array'] = vec_c_array
        msg['vec_s_array'] = vec_s_array
        msg['vec_c_lin'] = vec_c_lin
        msg['vec_s_lin'] = vec_s_lin
        msg['v_s'] = v_s
        return msg        
        
    def encryption(self, g_a_array, g_b_array, g_ab_array):
        q, g, h = self.pub_key
        vec_w_array = []
        vec_y_array = []
        vec_v_array = []
        
        for mu_array, g_a, g_b, g_ab in zip(self.vec_mu_array, g_a_array, g_b_array, g_ab_array):
            w_array = []
            y_array = []
            v_array = []
            for i in range(0, self.n):
                r = number.getRandomRange(1, q-1)
                s = number.getRandomRange(1, q-1)
                w = pow(g, r, q) * pow(g_a, s, q) % q
                v = pow(g_b, r, q) * pow(g_ab * pow(g, i-1, q) % q, s, q) % q
                y = pow(g, mu_array[i], q) * pow(h, v, q) % q
                w_array.append(w)
                y_array.append(y)
                v_array.append(v)

            vec_w_array.append(w_array)
            vec_y_array.append(y_array)
            vec_v_array.append(v_array)

        self.vec_w_array = vec_w_array
        self.vec_y_array = vec_y_array
        self.vec_v_array = vec_v_array

        return vec_w_array, vec_y_array
    
    def P1_a(self):
        q, g, h = self.pub_key
        vec_b_array = []
        vec_c_array = []
        vec_s_array = []
        vec_random_w_array = []
        for y_array, mu_array in zip(self.vec_y_array, self.vec_mu_array):
            b_array = []
            c_array = []
            s_array = []
            random_w_array = []            
            for y, mu in zip(y_array, mu_array):
                random_w = number.getRandomRange(1, q-1)
                if mu == 0:
                    c_1 = number.getRandomRange(1, q-1)
                    c_array.append(c_1)
                    s_1 = number.getRandomRange(1, q-1)
                    s_array.append(s_1)
                    b_0 = pow(h, random_w, q)
                    g_1_inv = pow(pow(g, 1, q), -1, q)
                    deno = pow(y * g_1_inv % q, c_1, q)
                    b_1 = pow(h, s_1, q) * pow(deno, -1, q) % q
                elif mu == 1:
                    c_0 = number.getRandomRange(1, q-1)
                    c_array.append(c_0)
                    s_0 = number.getRandomRange(1, q-1)
                    s_array.append(s_0)
                    b_1 = pow(h, random_w, q)
                    g_0_inv = pow(pow(g, 0, q), -1, q)
                    deno = pow(y * g_0_inv % q, c_0, q)
                    b_0 = pow(h, s_0, q) * pow(deno, -1, q) % q
                else:
                    assert False, "mu is invalid (0 or 1)"

                b_array.append((b_0, b_1))
                random_w_array.append(random_w)

            vec_b_array.append(b_array)
            vec_c_array.append(c_array)
            vec_s_array.append(s_array)
            vec_random_w_array.append(random_w_array)

        self.vec_b_array = vec_b_array
        self.vec_c_array = vec_c_array
        self.vec_s_array = vec_s_array
        self.vec_random_w_array = vec_random_w_array
        
        return vec_b_array
    
    def P1_c(self, vec_ak_p1_x_array):
        q, g, h = self.pub_key
        vec_c_array = []
        vec_s_array = []
        for ak_p1_x_array, c_array, s_array, mu_array , v_array , random_w_array in zip(
            vec_ak_p1_x_array,
            self.vec_c_array,
            self.vec_s_array,
            self.vec_mu_array,
            self.vec_v_array,
            self.vec_random_w_array
        ):
            c_array = []
            s_array = []
            for x,c,s,mu,v,random_w in zip(
                ak_p1_x_array,
                c_array,
                s_array,
                mu_array,
                v_array,
                random_w_array
            ):
                if mu == 0:
                    c_0 = (x - c)
                    c_1 = c
                    s_0 = ((v * c_0) + random_w)
                    s_1 = s
                elif mu == 1:
                    c_0 = c
                    c_1 = (x - c)
                    s_0 = s
                    s_1 = ((v * c_1) + random_w)
                else:
                    assert False, "error mu"
                
                c_array.append((c_0, c_1))
                s_array.append((s_0, s_1))
            
            vec_c_array.append(c_array)
            vec_s_array.append(s_array)
        return vec_c_array, vec_s_array
    
    def P2_a(self):
        q, g, h = self.pub_key
        vec_b_lin = []
        vec_c_lin = []
        vec_s_lin = []
        vec_random_w_lin = []
        for category, y_array in zip(self.categories, self.vec_y_array):
            random_w = number.getRandomRange(1, q-1)
            if category != self.data:
                c_p = number.getRandomRange(1, q-1)
                vec_c_lin.append(c_p)
                s_p = number.getRandomRange(1, q-1)
                vec_s_lin.append(s_p)
                g_p_inv = pow(pow(g, (self.n // 2), q), -1, q)
                commitment = 1
                for y in y_array:
                    commitment = commitment * y % q
                deno = pow(commitment * g_p_inv % q, c_p, q)
                b_p = pow(h, s_p, q) * pow(deno, -1, q) % q
                b_q = pow(h, random_w, q)
            else:
                c_q = number.getRandomRange(1, q-1)
                vec_c_lin.append(c_q)
                s_q = number.getRandomRange(1, q-1)
                vec_s_lin.append(s_q)
                g_q_inv = pow(pow(g, (self.l), q), -1, q)
                commitment = 1
                for y in y_array:
                    commitment = commitment * y % q
                deno = pow(commitment * g_q_inv % q, c_q, q)
                b_q = pow(h, s_q, q) * pow(deno, -1, q) % q
                b_p = pow(h, random_w, q)

            vec_b_lin.append((b_p, b_q))
            vec_random_w_lin.append(random_w)

        self.vec_c_lin = vec_c_lin
        self.vec_s_lin = vec_s_lin
        self.vec_b_lin = vec_b_lin
        self.vec_random_w_lin = vec_random_w_lin
        return vec_b_lin

    def P2_c(self, vec_ak_p2_x_lin):
        q, g, h = self.pub_key
        vec_c_lin = []
        vec_s_lin = []
        for category, c_lin, s_lin, v_array, random_w_lin, ak_p2_x_lin in zip(
            self.categories,
            self.vec_c_lin,
            self.vec_s_lin,
            self.vec_v_array,
            self.vec_random_w_lin,
            vec_ak_p2_x_lin
        ):
            if category == self.data:
                vec_c_lin.append((ak_p2_x_lin - c_lin, c_lin))
                v_sum = 0
                for v in v_array:
                    v_sum += v
                vec_s_lin.append((v_sum * (ak_p2_x_lin - c_lin) + random_w_lin, s_lin))
            else:
                vec_c_lin.append((c_lin, ak_p2_x_lin - c_lin))
                v_sum = 0
                for v in v_array:
                    v_sum += v
                vec_s_lin.append((s_lin, v_sum * (ak_p2_x_lin - c_lin) + random_w_lin))

        return vec_c_lin, vec_s_lin

    def p3_a(self):
        v_s = 0
        for v_array in self.vec_v_array:
            v_s += sum(v_array)
        return v_s

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


def runOnMemory(categories, epsilon, secret_input, width):
    d, l, n = buildOueParams(epsilon, width, categories)
    z = 0

    verifier = OueVerifier(categories, d, l, n, z)
    prover = OueProver(secret_input, categories, d, l, n, z)
    prover.setup()

    # Verifier
    start = time.time()
    msg = verifier.setup(security=80)
    verifier.loggingResult('setup time [s]', time.time() - start)
    size = len(pickle.dumps(msg))
    verifier.loggingResult('MESSAGE_TYPE.START size [B]', size)

    # Prover
    start = time.time()
    prover.setPubKey(msg['pub_key'])
    msg = prover.step1(msg)
    prover.loggingResult('step1 time [s]', time.time() - start)
    size = len(pickle.dumps(msg))
    prover.loggingResult('MESSAGE_TYPE.STEP1 size [B]', size)

    # Verifier
    start = time.time()
    msg = verifier.step2(msg)
    verifier.loggingResult('step2 time [s]', time.time() - start)
    size = len(pickle.dumps(msg))
    verifier.loggingResult('MESSAGE_TYPE.STEP2 size [B]', size)

    # Prover
    start = time.time()
    msg = prover.step3(msg)
    prover.loggingResult('step3 time [s]', time.time() - start)
    size = len(pickle.dumps(msg))
    prover.loggingResult('MESSAGE_TYPE.STEP3 size [B]', size)
 
    # Verifier
    start = time.time()
    msg = verifier.step4(msg)
    verifier.loggingResult('step4 time [s]', time.time() - start)
    size = len(pickle.dumps(msg))
    verifier.loggingResult('MESSAGE_TYPE.STEP4 size [B]', size)
    verifier.loggingResult('overall time', time.time() - verifier.clock)
    
    pprintResult(verifier.result)
    pprintResult(prover.result)

    return msg, verifier.result, prover.result


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Execute OLH on memory.')
    parser.add_argument('--cate_num', type=int, help="number of cateogories (default: 5)", default=5)
    parser.add_argument('--width', type=int, help="distribution accuracy parameter (default: 100)", default=100)
    parser.add_argument('--epsilon', type=float, help="privacy budget used in LDP protocol (default: 1.0)", default=1.0)
    parser.add_argument('--sensitive_value', type=int, help="sensitive value (default: 0)", default=0)
    args = parser.parse_args()

    cate_num = args.cate_num
    categories = list(range(0, cate_num))
    epsilon = args.epsilon
    secret_input = args.sensitive_value
    width = args.width

    msg, verifier_result, prover_result = runOnMemory(categories, epsilon, secret_input, width)
    saveJsonResult(verifier_result, dir_name='result', params=['onmemory', 'verifier', cate_num, epsilon, width, 'oue'])
    saveJsonResult(prover_result, dir_name='result', params=['onmemory', 'prover', cate_num, epsilon, secret_input, width, 'oue'])
    print(msg)