import logging

from androguard import misc
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.androconf import show_logging
from androguard.decompiler.dad.decompile import DvMachine

from allocatorUtil import read_pair_file, Pair
from util import *

import sys
from typing import List, Set, Dict, Tuple, Optional

show_logging(logging.FATAL)


def main():
    apk_file = sys.argv[1].strip()

    print("Decompiling APK...")
    apk_obj: APK
    dalv_format: List[DalvikVMFormat]
    dx: Analysis
    apk_obj, dalv_format, dx = misc.AnalyzeAPK(apk_file)


    print("Getting syntax tree...")
    machine = DvMachine(apk_file)

    ast = machine.get_ast()

    # get the main activity
    # This is the main activity for the app
    main_act = format_activity_name(apk_obj.get_main_activity())
    # class analysis of the main activity class
    main_analysis: ClassAnalysis = dx.get_class_analysis(main_act)

    main_package_pattern = '/'.join(main_act.split('/')[:2]) + '.*'
    print("Creating call graph...")
    cg = dx.get_call_graph()
    cg_filter = dx.get_call_graph(classname=main_package_pattern)


    resource_method_pairs = read_pair_file(dx, cg_filter)

    print("Analyzing callbacks...")

    filtered_methods = [x for x in dx.find_methods(classname=main_package_pattern)]
    for mca in filtered_methods:
        link_callbacks(mca, dx, ast, cg)

    # Get analyses for exit points.
    on_pause_analysis = find_method(main_analysis, "onPause")
    on_pause_method = None
    if on_pause_analysis:
        on_pause_method: EncodedMethod = on_pause_analysis.method

    on_stop_analysis = find_method(main_analysis, "onStop")
    on_stop_method = None
    if on_stop_analysis:
        on_stop_method: EncodedMethod = on_stop_analysis.method

    on_destroy_analysis = find_method(main_analysis, "onDestroy")
    on_destroy_method = None
    if on_destroy_analysis:
        on_destroy_method: EncodedMethod = on_destroy_analysis.method

    exit_methods = []
    if on_pause_method:
        exit_methods.append(on_pause_method)
    if on_stop_method:
        exit_methods.append(on_stop_method)
    if on_destroy_method:
        exit_methods.append(on_destroy_method)

    pair: Pair
    main_mcas: List[MethodClassAnalysis] = main_analysis.get_methods()
    for pair in resource_method_pairs:
        opener_paths = get_opener_paths(cg, main_mcas, pair)
        if opener_paths:
            open_paths, closed_paths = process_paths(cg, opener_paths, pair, exit_methods)
            if open_paths:
                # print out all the paths
                for path in open_paths:
                    print_allocation_path(path)


if __name__ == '__main__':
    main()
