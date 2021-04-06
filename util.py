import numpy as np
import math
from enum import Enum
from prettytable import PrettyTable
from datetime import datetime
import json
import pathlib


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
    tab.field_names = ["name", "value"]
    for k, v in result.items():
        tab.add_row([k, v])
    print(tab)

def buildFileName(params):
    return '-'.join([str(param) for param in params])

def saveJsonResult(result, dir_name='result', params=['']):
    tstmp = datetime.now().strftime('%Y%m%d%H%M%S')
    file_name = buildFileName(params)
    if dir_name:
        pathlib.Path(dir_name).mkdir(exist_ok=True)
        file_path = f'{dir_name}/{file_name}-{tstmp}.json'
    else:
        file_path = f'{file_name}-{tstmp}.json'
    with open(file_path, mode='w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)

def loadJsonResult(dir_name, params=['']):
    dir = pathlib.Path(dir_name)
    file_name = buildFileName(params)
    result_files = dir.glob(f'{file_name}-*.json')
    result_list = []
    for result_file in result_files:
        with open(result_file, 'r') as f:
            result = json.load(f)
            result_list.append(result)
    return result_list