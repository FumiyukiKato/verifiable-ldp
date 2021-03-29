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

def pprintResult(result):
    tab = PrettyTable()
    for k, v in result.items():
        tab.add_column(k, [v])
    print(tab)
