import numpy as np
import math
from enum import Enum
from prettytable import PrettyTable

class MESSAGE_TYPE(Enum):
    START = 1
    STEP1 = 2
    STEP2 = 3
    STEP3 = 4
    STEP4 = 5
    OK    = 6
    NG    = 7

def buildParams(epsilon, width, categories):
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

def pprintResult(result):
    tab = PrettyTable()
    for k, v in result.items():
        tab.add_column(k, [v])
    print(tab)
