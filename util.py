from typing import List, Set, Dict, Tuple, Optional, Union

from androguard.core.analysis.analysis import (
    Analysis,
    ClassAnalysis,
    ExternalMethod,
    MethodAnalysis,
    MethodClassAnalysis,
)
from androguard.core.bytecodes.dvm import EncodedMethod

import allocator_util

import networkx as nx
from callback_list import callback_list as android_callback_interfaces


# format of class name as stored in decompilation
def format_activity_name(name):
    return "L" + name.replace(".", "/") + ";"


# search AST for a specific method name
def get_method_from_ast(methodname: str, classname: str, ast: Dict):
    try:
        class_ast = ast[classname]
    except KeyError:
        return None
    for method in class_ast["methods"]:
        if method["triple"][1] == methodname:
            return method
    for interface in class_ast['interfaces']:
        interface_name, _ = interface[1]
        answer = get_method_from_ast(methodname, format_activity_name(interface_name), ast)
        if answer:
            return answer
    return None


# recursive search of AST for checking the type of a symbol
def get_ast_type(ast):
    if isinstance(ast, str):
        return ast
    node_type = ast[0]
    if node_type == "MethodInvocation":
        return get_ast_type(ast[2][2])
    if node_type == "FieldAccess":
        return get_ast_type(ast[2][2])
    if node_type == "ClassInstanceCreation":
        # ClassInstanceCreation has the format:
        # [
        #   'ClassInstanceCreation',
        #   arg1_ast, arg2_ast, ...,
        #   ['TypeName', (actual_type_string, integer)],
        # ]
        return ast[2][1][0]
    if node_type == "Cast":
        return get_ast_type(ast[1][0])
    if node_type == "Local":
        return "UNRESOLVED LOCAL"
    if node_type == "TypeName":
        return get_ast_type(ast[1][0])
    if node_type == "Literal":
        return get_ast_type(ast[2][0])
    if node_type == "Parenthesis":
        # unwrap parens
        return get_ast_type(ast[1][0])
    if node_type == "ExpressionStatement":
        return "UNRESOLVED EXPR STMT"
    return "failed, no case match"


# get the types of all args passed to a method
def get_method_arg_type(method_ast):
    if len(method_ast[1]) > 1:
        return list(map(get_ast_type, method_ast[1][1:]))
    else:
        # there's no method arguments
        return "No args"


def get_method_invocations(ast):
    if not isinstance(ast, list) or len(ast) == 0:
        return []
    ret = []
    if ast[0] == "MethodInvocation":
        ret.append(ast)
        ret.extend(get_method_invocations(ast[1:]))
    else:
        for item in ast:
            if isinstance(item, list):
                ret.extend(get_method_invocations(item))
    return ret


def get_callback_list(mca: MethodClassAnalysis, dx: Analysis, ast: Dict, callback_interfaces: List):
    classname: str = mca.method.class_name
    methodname: str = mca.name
    method_ast = get_method_from_ast(methodname, classname, ast)
    if method_ast:
        method_ast_body = method_ast['body']
    else:
        return []
    method_invocs = get_method_invocations(method_ast_body)

    registered_callbacks = []
    for invoc in method_invocs:
        arg_types = get_method_arg_type(invoc)
        for typ in arg_types:
            cls: ClassAnalysis = dx.get_class_analysis(typ)
            if isinstance(cls, ClassAnalysis):
                for interface in cls.implements:
                    if interface in callback_interfaces:
                        print(
                            "Found registered resource: ", typ, "implements ", interface
                        )
                        registered_callbacks.append((typ, interface))

    return registered_callbacks


def link_callbacks(mca: MethodClassAnalysis, dx: Analysis, ast: Dict, cg: nx.DiGraph):
    android_api_callbacks = get_cb_methods()
    invoked_callback_registers = get_callback_list(mca, dx, ast, android_callback_interfaces)

    def is_android_api_callback(callback_tuple):
        _, interface = callback_tuple
        if interface in android_api_callbacks:
            return True
        return False

    invoked_callback_registers = filter(is_android_api_callback, invoked_callback_registers)

    found_methods = list()
    for cb_typ, cb_interface in invoked_callback_registers:
        java_interface: JavaInterface = android_api_callbacks[cb_interface]
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

    for method_enc in found_methods:
        print("adding edge: ", mca.name, " -> ", method_enc.name)
        cg.add_edge(mca.method, method_enc)


def get_cb_methods():
    interface_to_methods = {}

    with open("./parseInterfaces/output/CallbackMethods.txt", "r") as f:
        line: str = f.readline()

        curr_interface = None
        curr_method = None
        while line:
            line = line.strip()

            if line == "INTERFACE":
                interface_name = f.readline().strip()
                curr_interface = JavaInterface(interface_name)
                interface_to_methods[interface_name] = curr_interface

            elif line == "METHOD":
                curr_method = JavaMethod(f.readline().strip())
                curr_interface.add_method(curr_method)

            elif line == "RETURN TYPE":
                curr_method.ret_type = f.readline().strip()

            elif line == "ARG TYPE":
                curr_method.add_arg(f.readline().strip())

            line = f.readline()

    return interface_to_methods


def find_method(analysis: ClassAnalysis, name: str) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == name:
            return meth
    return None


def add_cg_link(cg: nx.DiGraph,
                m1: EncodedMethod,
                m2: EncodedMethod):
    if m1 and m2:
        cg.add_edge(m1, m2)


def link_to_exit_methods(cg: nx.DiGraph,
                         m: EncodedMethod,
                         exit_methods: List[EncodedMethod]):
    for method in exit_methods:
        add_cg_link(cg, m, method)


def print_allocation_path(path: List[EncodedMethod]):
    print("PATH: ")
    for item in path[:-1]:
        print(item.name)
        print("↓")
    print(path[-1])
    print()


def get_entrypoints(methods: List[MethodClassAnalysis]):
    entrypoints: List[MethodClassAnalysis] = []
    mca:  MethodClassAnalysis
    for mca in methods:
        if mca.name[:2] == "on":
            entrypoints.append(mca)
    return entrypoints


def get_opener_paths(cg: nx.DiGraph, main_mcas: List[MethodClassAnalysis], pair: allocator_util.Pair):
    entrypoints = get_entrypoints(main_mcas)
    opener_paths: List[List[EncodedMethod]] = []

    for entrypoint in entrypoints:
        for opener in pair.openers:
            try:
                ssp = nx.shortest_simple_paths(cg, entrypoint.method, opener.method)
                opener_paths.extend([x for x in ssp])
            except nx.exception.NetworkXNoPath:
                pass
    return opener_paths


def path_exists(cg: nx.DiGraph,
                path: List[EncodedMethod],
                pair: allocator_util.Pair,
                exitpoints: List[EncodedMethod]):
    node: EncodedMethod
    # check if a closer is called directly from the same path
    for node in path:
        for closer in pair.closers:
            try:
                ssp = nx.shortest_simple_paths(cg, node, closer.method)
                closing_paths = [x for x in ssp]
                if closing_paths:
                    return True
            except nx.exception.NetworkXNoPath:
                pass
    # check if a closer is called from an exitpoint
    for exitpoint in exitpoints:
        for closer in pair.closers:
            try:
                ssp = nx.shortest_simple_paths(cg, exitpoint, closer.method)
                if [x for x in ssp]:
                    return True
            except nx.exception.NetworkXNoPath:
                pass

    return False


def process_paths(cg: nx.DiGraph,
                  opener_paths: List[List[EncodedMethod]],
                  pair: allocator_util.Pair,
                  exitpoints: List[EncodedMethod]):
    open_paths = []
    closed_paths = []
    for path in opener_paths:
        if path_exists(cg, path, pair, exitpoints):
            closed_paths.append(path)
        else:
            open_paths.append(path)
    return open_paths, closed_paths


def filter_with_cg(paths: List[List[EncodedMethod]], cg_filter: nx.DiGraph):
    return list(filter(lambda x: cg_filter.has_node(x[-2]), paths))


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


