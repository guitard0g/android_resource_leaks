from androguard.core.analysis.analysis import Analysis
from androguard import misc
from typing import List, Set, Dict, Tuple, Optional
from collections import defaultdict


class Pair(object):
    def __init__(self, opener: str, closers: List[str], classname: str, reference_dx: Analysis):
        self.classname = classname

        opener_analyses = reference_dx.find_methods(methodname=opener, classname=classname)
        self.openers = [x for x in opener_analyses]

        self.closers = []
        for closer in closers:
            closer_gen = reference_dx.find_methods(methodname=closer, classname=classname)
            self.closers.extend([x for x in closer_gen])

        self.opener_path_generators = []
        self.closer_path_generators = []
        self.lifecycles = []
        self.opener_paths = []
        self.closer_paths = []


def read_pair_file(reference_dx: Analysis) -> List[Pair]:
    method_pairs = []
    opener_to_closer = defaultdict(list)
    with open("./parseInterfaces/output/pairs.txt", 'r') as f:
        line = f.readline().strip()
        while line:
            # map classname * opener => [potential_closers...]
            (classname, opener, closer) = line.split(" ## ")
            opener_to_closer[(classname, opener)].append(closer)
            line = f.readline().strip()
        for classname_opener, closers in opener_to_closer.items():
            # create Pair objects for the gathered map of opener to closer_list
            classname, opener = classname_opener
            pair = Pair(opener, closers, classname, reference_dx)
            if pair.openers and pair.closers:
                method_pairs.append(pair)
    return method_pairs


if __name__=="__main__":
    _, _, dx = misc.AnalyzeAPK("./testApks/app-debug.apk")
    pairs = read_pair_file(dx)

