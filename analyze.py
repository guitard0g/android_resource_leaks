import logging

from androguard import misc
from androguard.core.analysis.analysis import (
    ClassAnalysis,
    ExternalMethod,
    MethodAnalysis,
    MethodClassAnalysis,
)
from androguard.core.androconf import show_logging
from androguard.core.bytecodes.dvm import EncodedMethod
from androguard.decompiler.dad.decompile import DvMachine
from networkx import shortest_simple_paths

from callback_list import callback_list as android_callback_list
from allocatorUtil import read_pair_file, Pair
from util import *

import sys
from typing import List, Set, Dict, Tuple, Optional

show_logging(logging.FATAL)


def main():
    apk_file = sys.argv[1].strip()

    print("Decompiling APK...")
    apk_obj, dalv_format, dx = misc.AnalyzeAPK(apk_file)

    cg = dx.get_call_graph()

    print("Getting syntax tree...")
    machine = DvMachine(apk_file)

    ast = machine.get_ast()

    resource_method_pairs = read_pair_file(dx)

    # get the main activity
    # This is the main activity for the app
    main_act = format_activity_name(apk_obj.get_main_activity())
    # class analysis of the main activity class
    main_analysis: ClassAnalysis = dx.get_class_analysis(main_act)

    print("Analyzing callbacks...")

    # ALL OF THIS INFORMATION ABOUT AVAILABLE CALLBACKS IS
    # PREPROCESSED FROM parseInterfaces
    # Get all interfaces that onCreate implements
    cbs = get_registered_callbacks(main_act, "onCreate", dx, ast, android_callback_list)
    # parse out all of the methods that each interface has
    # returns dictionary {interface => method list}
    cb_methods = get_cb_methods()

    # now grab the analysis of the onCreate method
    on_create_search = dx.find_methods(classname=main_act, methodname="onCreate$")
    on_create: MethodClassAnalysis
    for item in on_create_search:
        on_create = item
    on_create_enc = on_create.method

    found_methods = list()

    # Look at all callbacks in onCreate
    for cb_typ, cb_interface in cbs:
        if cb_interface in cb_methods:
            java_interface: JavaInterface = cb_methods[cb_interface]
        else:
            continue
        interface_method: JavaMethod

        # Try to find the analysis for the interface methods.
        # This should be successful if an interface method is
        # used by any user code, but I'll need to verify edge cases.
        for interface_method in java_interface.methods:
            gen = dx.find_methods(
                classname=cb_typ, methodname=".*{}.*".format(interface_method.name)
            )
            analysis: MethodClassAnalysis
            found = False
            for item in gen:
                analysis = item
                found = True
            if found:
                found_methods.append(analysis.method)

    # Add an edge in the FCG from on_create to the callback method
    for method_enc in found_methods:
        print("adding edge: ", on_create_enc.name, " -> ", method_enc.name)
        cg.add_edge(on_create_enc, method_enc)

    on_create_analysis = find_method(main_analysis, "onCreate")
    on_create_method: EncodedMethod = on_create_analysis.method

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
