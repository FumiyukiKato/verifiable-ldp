import unittest
import sys
sys.path.append('../')
import olh
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
        g = 5
        msg, _, _ = olh.runOnMemory(categories, epsilon, secret_input, width, g)
        self.assertEqual(msg['type'], MESSAGE_TYPE.OK, 'It should be OK')

if __name__ == "__main__":
    unittest.main()