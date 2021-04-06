import unittest
import sys
sys.path.append('../')
import krr
from util import MESSAGE_TYPE

class TestKrr(unittest.TestCase):

    def setUp(self):
        pass

    def test_ok(self):
        cate_num = 10
        categories = list(range(0, cate_num))
        epsilon = 1.0
        secret_input = 2
        width = 100
        msg, _, _ = krr.runOnMemory(categories, epsilon, secret_input, width)
        self.assertEqual(msg['type'], MESSAGE_TYPE.OK, 'It should be OK')

if __name__ == "__main__":
    unittest.main()