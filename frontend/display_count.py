#!/usr/bin/env python
# -*- coding: utf-8 -*-

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import sys
import csv
from datetime import datetime

def check_argv():
    if len(sys.argv) < 2:
        print("Error: add file to display")
        sys.exit(1)

def load_file():
    with open(sys.argv[1], 'r') as f:
        reader = csv.reader(f, delimiter=',')
        l = list(reader)
    return l

if __name__ == "__main__":
    check_argv()
    l = load_file()
    matplotlib.rcParams.update({'figure.figsize' : [8, 5]})
    # No Type 3 font
    matplotlib.rcParams['pdf.fonttype'] = 42
    matplotlib.rcParams['ps.fonttype'] = 42

    times = [datetime.fromtimestamp(float(x[0])) for x in l]
    node1 = [x[1] for x in l]
    total = [sum([int(y) for y in x[1:-1]]) for x in l]
    plt.plot(times, node1)
    plt.plot(times, total)
    
    plt.legend()
    plt.tight_layout()
    plt.show()
