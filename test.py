import logging
import re
from collections import defaultdict
from pprint import pprint
from typing import Union

from androguard import misc
from androguard.core.analysis.analysis import (ClassAnalysis, ExternalMethod,
                                               MethodAnalysis,
                                               MethodClassAnalysis)
from androguard.core.androconf import show_logging
from androguard.core.bytecodes.dvm import EncodedMethod
from androguard.decompiler.dad.decompile import DvMachine
from networkx import shortest_simple_paths

from callback_list import callback_list as android_callback_list

show_logging(logging.FATAL)


def format_activity_name(name):
    return "L" + name.replace('.', '/') + ";"


apk_file = str(input("Input name of apk: ")).strip()

print("Decompiling APK...")
apk_obj, dalv_format, dx = misc.AnalyzeAPK(apk_file)

cg = dx.get_call_graph()

print("Getting syntax tree...")
machine = DvMachine(apk_file)

# get the main activity
main_act = format_activity_name(apk_obj.get_main_activity())
main_analysis: ClassAnalysis = dx.get_class_analysis(main_act)


def get_method_from_ast(class_ast, name):
    for method in class_ast['methods']:
        if method['triple'][1] == name:
            return method


def get_method_name_from_ast(method_ast):
    return method_ast['triple'][1]


def get_class_methods_ast(class_ast):
    return class_ast['methods']


def get_ast_type(ast):
    if isinstance(ast, str):
        return ast
    node_type = ast[0]
    if node_type == 'MethodInvocation':
        return get_ast_type(ast[2][2])
    if node_type == 'FieldAccess':
        return get_ast_type(ast[2][2])
    if node_type == 'ClassInstanceCreation':
        return get_ast_type(ast[1][0])
    if node_type == 'Cast':
        return get_ast_type(ast[1][0])
    if node_type == 'Local':
        return 'UNRESOLVED LOCAL'
    if node_type == 'TypeName':
        return get_ast_type(ast[1][0])
    if node_type == 'Literal':
        return get_ast_type(ast[2][0])
    if node_type == 'Parenthesis':
        # unwrap parens
        return get_ast_type(ast[1][0])
    if node_type == 'ExpressionStatement':
        return 'UNRESOLVED EXPR STMT'
    return 'failed, no case match'


def get_method_arg_type(method_ast):
    if len(method_ast[1]) > 1:
        return list(map(get_ast_type, method_ast[1][1:]))
    else:
        # there's no method arguments
        return 'No args'


def get_method_invocations(ast):
    if not isinstance(ast, list) or len(ast) == 0:
        return []
    ret = []
    if ast[0] == 'MethodInvocation':
        ret.append(ast)
        ret.extend(get_method_invocations(ast[1:]))
    else:
        for item in ast:
            if isinstance(item, list):
                ret.extend(get_method_invocations(item))
    return ret


ast = machine.get_ast()


def get_registered_callbacks(classname,
                             methodname,
                             ast=ast,
                             callback_list=android_callback_list):
    registered_callbacks = []
    method_ast_body = get_method_from_ast(ast[classname], methodname)['body']
    method_invocs = get_method_invocations(method_ast_body)
    for invoc in method_invocs:
        arg_types = get_method_arg_type(invoc)
        for typ in arg_types:
            cls: ClassAnalysis = dx.get_class_analysis(typ)
            if isinstance(cls, ClassAnalysis):
                for interface in cls.implements:
                    if interface in callback_list:
                        print("Found registered resource: ", typ, "implements ", interface)
                        registered_callbacks.append((typ, interface))
    return registered_callbacks


class JavaMethod(object):
    def __init__(self, name):
        self.name = name
        self.args = list()
        self.ret_type = None

    def add_arg(self, arg):
        self.args.append(arg)

    def __repr__(self):
        return "Method " + self.name + ", Args " + str(self.args)


class JavaInterface(object):
    def __init__(self, name):
        self.name = name
        self.methods = list()

    def add_method(self, method):
        self.methods.append(method)

    def __repr__(self):
        return self.name + ": " + str(self.methods)


def get_cb_methods():
    interface_to_methods = {}

    with open("./parseInterfaces/output/CallbackMethods.txt", "r") as f:
        line: str = f.readline()

        curr_interface = None
        curr_method = None
        while line:
            line = line.strip()

            if line == 'INTERFACE':
                interface_name = f.readline().strip()
                curr_interface = JavaInterface(interface_name)
                interface_to_methods[interface_name] = curr_interface

            elif line == 'METHOD':
                curr_method = JavaMethod(f.readline().strip())
                curr_interface.add_method(curr_method)

            elif line == 'RETURN TYPE':
                curr_method.ret_type = f.readline().strip()

            elif line == 'ARG TYPE':
                curr_method.add_arg(f.readline().strip())

            line = f.readline()

    return interface_to_methods


print("Analyzing callbacks...")
cbs = get_registered_callbacks(main_act, "onCreate")
cb_methods = get_cb_methods()

on_create_search = dx.find_methods(classname=main_act, methodname="onCreate$")
on_create: MethodClassAnalysis
for item in on_create_search:
    on_create = item
on_create_enc = on_create.method

found_methods = list()

for cb_typ, cb_interface in cbs:
    if cb_interface in cb_methods:
        java_interface: JavaInterface = cb_methods[cb_interface]
    else:
        continue
    interface_method: JavaMethod

    for interface_method in java_interface.methods:
        gen = dx.find_methods(classname=cb_typ, methodname=".*{}.*".format(interface_method.name))
        analysis: MethodClassAnalysis
        found = False
        for item in gen:
            analysis = item
            found = True
        if found:
            found_methods.append(analysis.method)

for method_enc in found_methods:
    print("adding edge: ", on_create_enc.name, " -> ", method_enc.name)
    cg.add_edge(on_create_enc, method_enc)


closers = dx.find_methods(methodname="^(end|abandon|cancel|clear|close|disable|finish|recycle|release|remove|stop|unload|unlock|unmount|unregister).*")
openers = dx.find_methods(methodname="^(start|request|lock|open|register|acquire|vibrate|enable).*")


def find_onCreate(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == 'onCreate':
            return meth
    return None


def find_onPause(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == 'onPause':
            return meth
    return None


def find_onStop(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == 'onStop':
            return meth
    return None


def find_onDestroy(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == 'onDestroy':
            return meth
    return None


def find_getCam(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == 'getCameraInstance':
            return meth


def get_MethodAnalysis(method: Union[EncodedMethod, ExternalMethod]) -> MethodAnalysis:
    return dx.get_method(method)


def get_MethodClassAnalysis(method: Union[EncodedMethod, ExternalMethod]) -> MethodClassAnalysis:
    return dx.get_method_analysis(method)


def search_cfg(method: MethodClassAnalysis) -> None:
    searched_cfg = False
    if method.full_name not in seen_methods:
        seen_methods.add(method.full_name)
        for _, call, _ in method.get_xref_to():
            for i in dx.find_methods(methodname=call.name, classname=call.class_name):
                # if i.full_name in opener_names:
                #     print("opener: ", i.full_name)
                # if i.full_name in closer_names:
                #     print("closer: ", i.full_name)
                searched_cfg = True
                search_cfg(i, set(seen_methods))
    if not searched_cfg:
        print(len(seen_methods))


seen_methods = set()

on_create_analysis = find_onCreate(main_analysis)
on_create_method: EncodedMethod = on_create_analysis.method

on_pause_analysis = find_onPause(main_analysis)
on_pause_method = None
if on_pause_analysis:
    on_pause_method: EncodedMethod = on_pause_analysis.method

on_stop_analysis = find_onStop(main_analysis)
on_stop_method = None
if on_stop_analysis:
    on_stop_method: EncodedMethod = on_stop_analysis.method

on_destroy_analysis = find_onDestroy(main_analysis)
on_destroy_method = None
if on_destroy_analysis:
    on_destroy_method: EncodedMethod = on_destroy_analysis.method


def add_cg_link(m1, m2):
    if m1 and m2:
        cg.add_edge(m1, m2)


class ResourceLifecycle(object):
    def __init__(self,
                 source=None,
                 allocator=None,
                 deallocator=None,
                 allocation_caller=None,
                 allocation_path=None,
                 deallocation_path=None):
        self.source = source
        self.allocator = allocator
        self.deallocator = deallocator
        self.allocation_caller = allocation_caller
        self.allocation_path = allocation_path
        self.deallocation_path = deallocation_path

    def add_deallocation_path(self, path_generator):
        try:
            for path in path_generator:
                self.deallocator = path[-1]
                self.deallocation_path = path
        except Exception:
            pass

    def is_closed(self):
        if not self.deallocation_path:
            return False
        else:
            return True

    def get_full_path(self):
        return self.allocation_path[:-1] + self.deallocation_path

    def print_lifecycle(self):
        assert self.source is not None
        assert self.allocator is not None
        assert self.deallocator is not None
        assert self.allocation_caller is not None
        assert self.allocation_path is not None
        assert self.deallocation_path is not None
        if not self.is_closed():
            print("Resource not closed: ", self.allocator)
        else:
            print("PATH: ")
            for item in self.allocation_path[:-2]:
                print(item.name)
                print("↓")
            print(self.allocation_caller.name, " → ", self.allocator.name)
            for item in self.deallocation_path[1:]:
                print("↓")
                print(item.name)

    def print_allocation_path(self):
        assert self.allocation_path is not None
        print("PATH: ")
        for item in self.allocation_path[:-1]:
            print(item.name)
            print("↓")
        print(self.allocation_path[-1])

    def __repr__(self):
        return str(self.source.name) + " -> " + str(
            self.allocator.name) + " -> " + str(
                self.deallocator.name) + ", Branch: " + str(
                    self.allocation_caller.name) + " -> " + str(
                        self.allocator.name)


# find entrypoint -> opener paths
# source/sink traversal
print("Searching for entrypoint -> resource request paths")
path_generators = []
for opener in openers:
    for methodAnal in main_analysis.get_methods():
        path_generators.append(shortest_simple_paths(cg, methodAnal.method, opener.method))

lifecycles = []
for gen in path_generators:
    empty = True
    try:
        for path in gen:
            lifecycles.append(
                ResourceLifecycle(
                    source=path[0],
                    allocator=path[-1],
                    allocation_caller=path[-2],
                    allocation_path=path))
    except Exception:
        continue

opener_re = re.compile("^(start|request|lock|open|register|acquire|vibrate|enable)")

allocation_check = defaultdict(lambda: False)
print("Searching for resource request -> resource release paths")
for l in lifecycles:
    classname = l.allocator.get_class_name()
    suffix = opener_re.sub('', l.allocator.name)
    matches = dx.find_methods(
        methodname=
        "^(end|abandon|cancel|clear|close|disable|finish|recycle|release|remove|stop|unload|unlock|unmount|unregister)"
        + suffix + "$",
        classname=classname)
    for match in matches:
        l.add_deallocation_path(shortest_simple_paths(cg, l.allocation_caller, match.method))
    allocation_check[l.allocator] = allocation_check[l.allocator] or l.is_closed


has_leaks = False
for l in lifecycles:
    if not allocation_check[l.allocator]:
        has_leaks = True
        print("Resource path not closed: ")
        l.print_allocation_path()
    # else:
    #     l.print_lifecycle()

if not has_leaks:
    print("All good!")
