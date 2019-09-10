import logging
import re
from collections import defaultdict

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

show_logging(logging.FATAL)

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


# Find all methods that open and close system resources.
closers = dx.find_methods(
    methodname="^(end|abandon|cancel|clear|close|disable|finish|recycle|release|remove|stop|unload|unlock|unmount|unregister).*"
)
openers = dx.find_methods(
    methodname="^(start|request|lock|open|register|acquire|vibrate|enable).*"
)


seen_methods = set()

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


# find entrypoint -> opener paths
# source/sink traversal
print("Searching for entrypoint -> resource request paths")
# Look at each pair of entrypoint -> opener and
# create a generator that yields all paths from the entrypoint
# to that opener in the FCG
path_generators = []
for opener in openers:
    methodAnal: MethodClassAnalysis
    for methodAnal in main_analysis.get_methods():
        if methodAnal.name[:2] == "on":  # entrypoint method
            path_generators.append(
                shortest_simple_paths(cg, methodAnal.method, opener.method)
            )

# Initialize a ResourceLifecycle for each
# (entrypoint, opener) pair 
lifecycles = []
for gen in path_generators:
    empty = True
    try:
        for path in gen:
            method: EncodedMethod = path[-2]
            methodAnal: MethodClassAnalysis = dx.get_method_analysis(method)
            if not methodAnal.is_android_api() and not methodAnal.is_external():
                lifecycles.append(
                    ResourceLifecycle(
                        source=path[0],
                        # Method that allocates the resource
                        # is the last method in the path.
                        allocator=path[-1],
                        # Keep track of the method that called
                        # the allocator so that we know where to resume
                        # execution flow from. This is a VERY weak
                        # attempt at accounting for a closer being called
                        # later in some arbitrary path of execution.
                        allocation_caller=path[-2],
                        # Of course, keep the path
                        allocation_path=path,
                    )
                )
            # Link any allocation caller to the exit methods 
            link_to_exit_methods(path[-2])
    except Exception:
        continue

opener_re = re.compile("^(start|request|lock|open|register|acquire|vibrate|enable)")

allocation_check = defaultdict(lambda: False)
print("Searching for resource request -> resource release paths")
for l in lifecycles:
    classname = l.allocator.get_class_name()
    suffix = opener_re.sub("", str(l.allocator.name))
    matches = dx.find_methods(
        methodname="^(end|abandon|cancel|clear|close|disable|finish|recycle|release|remove|stop|unload|unlock|unmount|unregister)"
        + suffix
        + "$",
        classname=classname,
    )
    for match in matches:
        l.add_deallocation_path(
            shortest_simple_paths(cg, l.allocation_caller, match.method)
        )
    allocation_check[l.allocator] = allocation_check[l.allocator] or l.is_closed()


print("Checking lifecycles for leaks...")
has_leaks = False
seen = set()
for l in lifecycles:
    if not allocation_check[l.allocator] and l.allocator not in seen:
        has_leaks = True
        print("")
        print("Resource path not closed: ")
        l.print_allocation_path()
        seen.add(l.allocator)


if not has_leaks:
    print("All good!")
