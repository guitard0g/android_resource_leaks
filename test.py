import logging
import pdb
import re
import sys
from pprint import pprint
from typing import Union

from androguard import misc
from androguard.core.analysis.analysis import (ClassAnalysis, ExternalMethod,
                                               MethodAnalysis,
                                               MethodClassAnalysis)
from androguard.core.androconf import show_logging
from androguard.core.bytecodes.dvm import EncodedMethod
from androguard.decompiler.dad.decompile import DvMachine, DvMethod
from networkx import shortest_simple_paths

from callback_list import callback_list as android_callback_list

show_logging(logging.FATAL)


def format_activity_name(name):
    return "L" + name.replace('.', '/') + ";"


apk_file = "./app-debug.apk"

# apk_obj, dalv_format, dx = misc.AnalyzeAPK("./app-release-unsigned.apk")
apk_obj, dalv_format, dx = misc.AnalyzeAPK(apk_file)

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
# takepic_ast_body = get_method_from_ast(ast[main_act], 'takePicture')['body']
# main_ast_body = get_method_from_ast(ast[main_act], 'onCreate')['body']
# for method_ast in get_class_methods_ast(ast[main_act]):
#     # print("Invocations in: ", get_method_name_from_ast(method_ast))
#     method_invocs = get_method_invocations(method_ast['body'])
#     for invoc in method_invocs:
#         print("Method triple: ", invoc[2])
#         arg_types = get_method_arg_type(invoc)
#         # print("\t", arg_types)
#         for typ in arg_types:
#             cls: ClassAnalysis = dx.get_class_analysis(typ)
#             if isinstance(cls, ClassAnalysis):
#                 print("class " + typ + " implements: ", cls.implements)


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
                        registered_callbacks.append((typ, interface))
    return registered_callbacks


cbs = get_registered_callbacks(main_act, "onCreate")
cb = cbs[0][1]
print(cb)
pdb.set_trace()


# print(get_method_arg_type(main_ast_body[-1][0][1]))
# print(get_method_arg_type(main_ast_body[-1][-3][1]))
# takepic_ast_body = get_method_from_ast(ast[main_act], 'takePicture')['body']
# pprint(takepic_ast_body)
sys.exit()


closers = dx.find_methods(methodname="^(end|abandon|cancel|clear|close|disable|finish|recycle|release|remove|stop|unload|unlock|unmount|unregister).*")
openers = dx.find_methods(methodname="^(start|request|lock|open|register|acquire|vibrate|enable).*")




# game plan
# start at main entrypoint
# get oncreate
# initialize empty set of seen methods (must be unique identifiers)
# start search through xrefs in onCreate
# look for openers and closers used
# match openers to closers

# import pdb; pdb.set_trace()


def find_onCreate(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == 'onCreate':
            return meth


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


# def search_cg(method: MethodClassAnalysis) -> None:

# import pdb; pdb.set_trace()

seen_methods = set()

for field in main_analysis.get_fields():
    if field.name == 'mPreview':
        pdb.set_trace()

on_create_analysis = find_onCreate(main_analysis)
on_create_method: EncodedMethod = on_create_analysis.method
for _, call, _ in on_create_analysis.get_xref_to():
    for i in dx.find_methods(methodname=call.name, classname=call.class_name):
        pass
    if call.name == 'addView':
        pdb.set_trace()


class SourceSink(object):
    def __init__(self, source, sink):
        self.paths = []
        self.source = source
        self.sink = sink

    def add_path(self, path):
        self.paths.append(path)

    def __repr__(self):
        return "Source: " + str(self.source.name) + ", Sink: " + str(self.sink.name)


# find entrypoint -> opener paths
# source/sink traversal
cg = dx.get_call_graph()
path_generators = []
for opener in openers:
    for methodAnal in main_analysis.get_methods():
        path_generators.append(shortest_simple_paths(cg, methodAnal.method, opener.method))

on_create_source_sinks = []
for gen in path_generators:
    empty = True
    try:
        for path in gen:
            if empty:
                ss = SourceSink(path[0], path[-1])
                empty = False
            ss.add_path(path)
        on_create_source_sinks.append(ss)
    except Exception:
        continue

opener_re = re.compile("^(start|request|lock|open|register|acquire|vibrate|enable)")

path_generators = []
for ss in on_create_source_sinks:
    sink = str(ss.sink.name)
    classname = ss.sink.get_class_name()
    suffix = opener_re.sub('', sink)
    print(ss.sink)
    matches = dx.find_methods(methodname="^(end|abandon|cancel|clear|close|disable|finish|recycle|release|remove|stop|unload|unlock|unmount|unregister)" + suffix + "$", classname=classname)
    for match in matches:
        print("checking: ", classname, ss.sink.name, match.method.name)
        path_generators.append(shortest_simple_paths(cg, ss.sink, match.method))

opener_source_sinks = []
for gen in path_generators:
    empty = True
    try:
        for path in gen:
            if empty:
                ss = SourceSink(path[0], path[-1])
                empty = False
            ss.add_path(path)
        opener_source_sinks.append(ss)
    except Exception:
        continue

for ss in opener_source_sinks:
    print(ss)




# SCRATCH SPACE

# for method in main_analysis.get_methods():
#     print('searching method: ', method.full_name)
#     seen_methods = set()
#     search_cfg(method, seen_methods)


# search_cfg(on_create_analysis)
# print(len(seen_methods))

# https://source.android.com/devices/tech/dalvik/dex-format#access-flags
# ACCESS_FLAGS = {
#     0x1: 'public',
#     0x2: 'private',
#     0x4: 'protected',
#     0x8: 'static',
#     0x10: 'final',
#     0x20: 'synchronized',
#     0x40: 'bridge',
#     0x80: 'varargs',
#     0x100: 'native',
#     0x200: 'interface',
#     0x400: 'abstract',
#     0x800: 'strictfp',
#     0x1000: 'synthetic',
#     0x4000: 'enum',
#     0x8000: 'unused',
#     0x10000: 'constructor',
#     0x20000: 'synchronized',
# }

# https://source.android.com/devices/tech/dalvik/dex-format#typedescriptor
# TYPE_DESCRIPTOR = {
#     'V': 'void',
#     'Z': 'boolean',
#     'B': 'byte',
#     'S': 'short',
#     'C': 'char',
#     'I': 'int',
#     'J': 'long',
#     'F': 'float',
#     'D': 'double',
# }
