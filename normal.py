from Crypto.Util import number
import Crypto.Random as Random
import numpy as np
import math
import time
import pickle

from simpleByteProtocol import simpleRecv, simpleSend
from util import MESSAGE_TYPE, pprintResult, saveJsonResult

class NormalVerifier:
    def __init__(self, categories, d, l, n, z):
        self.categories, self.d = categories, d
        self.clock = time.time()
        self.result = {}
    
    def step1(self, msg):
        msg = {'type': MESSAGE_TYPE.STEP1}
        return msg

    def ok(self, msg):
        msg = {'type': MESSAGE_TYPE.OK}
        return msg   
    
    def messageHandler(self, conn, **kwargs):
        is_end = False
        msg, size = simpleRecv(conn)
        if msg == None:
            is_end = True
        elif msg['type'] == MESSAGE_TYPE.START:
            start = time.time()
            msg_to_be_send = self.step1(msg)
            self.loggingResult('setup time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.START size [B]', size)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.STEP2:
            start = time.time()
            msg_to_be_send = self.ok(msg)
            self.loggingResult('setup time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.START size [B]', size)
            simpleSend(conn, msg_to_be_send)
        else:
            assert False, "Invalid message type"
        return is_end
    
    def loggingResult(self, k, v):
        self.result[k] = v


class NormalProver:
    def __init__(self, data, categories, d, l, n, z):
        if data in categories:
            self.data = data
        else:
            assert False, "out of categories"
        self.categories, self.d = categories, d
        self.clock = time.time()
        self.result = {}

    def setup(self):
        pass
        
    def step2(self, msg):
        eps = 1.0
        randomized_data = self.kRR(self.data, eps)

        msg = {'type': MESSAGE_TYPE.STEP2}
        msg['randomized_data'] = randomized_data
        return msg

    def kRR(self, sensitive_data, eps):
        rand_num = np.random.rand()
        ratio = np.exp(eps) / (self.d - 1 + np.exp(eps))
        if ratio > rand_num:
            return sensitive_data
        else:
            return np.random.choice(list(filter(lambda x: x!=sensitive_data, self.categories)))

    def messageHandler(self, conn):
        is_end = False
        msg, size = simpleRecv(conn)
        if msg['type'] == MESSAGE_TYPE.STEP1:
            start = time.time()
            msg_to_be_send = self.step2(msg)
            self.loggingResult('step1 time [s]', time.time() - start)
            self.loggingResult('MESSAGE_TYPE.STEP1 size [B]', size)
            simpleSend(conn, msg_to_be_send)
        elif msg['type'] == MESSAGE_TYPE.OK:
            is_end = True
        else:
            assert False, "Invalid message type"
        return is_end

    def loggingResult(self, k, v):
        self.result[k] = v
