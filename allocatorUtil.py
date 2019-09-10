from androguard.core.analysis.analysis import Analysis
from androguard import misc
from typing import List, Set, Dict, Tuple, Optional


class Pair(object):
    def __init__(self, opener: str, closer: str, classname: str, reference_dx: Analysis):
        self.classname = classname
        closer_analyses = reference_dx.find_methods(methodname=closer, classname=classname)
        opener_analyses = reference_dx.find_methods(methodname=opener, classname=classname)
        self.closers = [x for x in closer_analyses]
        self.openers = [x for x in opener_analyses]


def read_pair_file(reference_dx: Analysis) -> List[Pair]:
    method_pairs = []
    with open("./parseInterfaces/output/method_pairs.txt", 'r') as f:
        line = f.readline().strip()
        while line:
            (classname, opener, closer) = line.split(" ## ")
            method_pairs.append(Pair(opener, closer, classname, reference_dx))
            line = f.readline().strip()
    return method_pairs


if __name__=="__main__":
    _, _, dx = misc.AnalyzeAPK("./testApks/app-debug.apk")
    pairs = read_pair_file(dx)

