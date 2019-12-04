from androguard.core.analysis.analysis import Analysis
from androguard import misc
from typing import List, Set, Dict, Tuple, Optional
from collections import defaultdict
from networkx import DiGraph

from androguard.core.bytecodes.dvm import EncodedMethod
from androguard.core.analysis.analysis import (
    Analysis,
    FieldClassAnalysis,
    MethodClassAnalysis,
)
EncodedClearsSets = Tuple[List[EncodedMethod], List[EncodedMethod]]
ClearsSets = Tuple[List[MethodClassAnalysis], List[MethodClassAnalysis]]
StaticFieldWriteInfo = Dict[FieldClassAnalysis, ClearsSets]


class Pair(object):
    def __init__(self, opener: str,
                 closers: List[str],
                 classname: str,
                 reference_dx: Analysis = None,
                 cg_filter: DiGraph = None):
        if reference_dx:
            self.classname = classname
            opener_analyses = reference_dx.find_methods(methodname=opener, classname=classname)
            self.openers = [x for x in opener_analyses]

            self.closers = []
            for closer in closers:
                closer_gen = reference_dx.find_methods(methodname=closer, classname=classname)
                self.closers.extend([x for x in closer_gen])

            # optionally filter out uninteresting openers based on
            # if they exist in a given call graph
            if cg_filter:
                self.openers = list(filter(lambda x: cg_filter.has_node(x.method), self.openers))

        self.opener_path_generators = []
        self.closer_path_generators = []
        self.lifecycles = []
        self.opener_paths = []
        self.closer_paths = []

    @staticmethod
    def empty():
        return Pair('', [], '')

    @staticmethod
    def from_write_info(write_info: StaticFieldWriteInfo):
        pairs = []
        for k, v in write_info.items():
            pair = Pair.empty()
            clears, sets = v
            pair.openers = sets
            pair.closers = clears
            pair.field = k
            pairs.append(pair)
        return pairs


def read_pair_file(reference_dx: Analysis, cg_filter: DiGraph = None) -> List[Pair]:
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
            pair = Pair(opener, closers, classname, reference_dx, cg_filter)
            if pair.openers:
                method_pairs.append(pair)

    return method_pairs


if __name__=="__main__":
    _, _, dx = misc.AnalyzeAPK("./testApks/app-debug.apk")
    pairs = read_pair_file(dx)

