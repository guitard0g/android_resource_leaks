from typing import List, Set, Dict, Tuple, Optional, Union

from androguard.core.analysis.analysis import (
    Analysis,
    ClassAnalysis,
    ExternalMethod,
    MethodAnalysis,
    MethodClassAnalysis,
)
from androguard.core.bytecodes.dvm import EncodedMethod

from allocatorUtil import Pair

import networkx as nx

# format of class name as stored in decompilation
def format_activity_name(name):
    return "L" + name.replace(".", "/") + ";"


# search AST for a specific method name
def get_method_from_ast(class_ast, name):
    for method in class_ast["methods"]:
        if method["triple"][1] == name:
            return method


# get string name from AST of a method
def get_method_name_from_ast(method_ast):
    return method_ast["triple"][1]


# get methods of a class
def get_class_methods_ast(class_ast):
    return class_ast["methods"]


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
        return get_ast_type(ast[1][0])
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


def get_registered_callbacks(
        classname, methodname, dx, ast, callback_list
):
    registered_callbacks = []
    method_ast_body = get_method_from_ast(ast[classname], methodname)["body"]
    method_invocs = get_method_invocations(method_ast_body)
    for invoc in method_invocs:
        arg_types = get_method_arg_type(invoc)
        for typ in arg_types:
            cls: ClassAnalysis = dx.get_class_analysis(typ)
            if isinstance(cls, ClassAnalysis):
                for interface in cls.implements:
                    if interface in callback_list:
                        print(
                            "Found registered resource: ", typ, "implements ", interface
                        )
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


def find_getCam(analysis: ClassAnalysis) -> MethodClassAnalysis:
    meth: MethodClassAnalysis
    for meth in analysis.get_methods():
        if meth.name == "getCameraInstance":
            return meth


def get_MethodAnalysis(dx: Analysis,
                       method: Union[EncodedMethod, ExternalMethod]
                       ) -> MethodAnalysis:
    return dx.get_method(method)


def get_MethodClassAnalysis(dx: Analysis,
                            method: Union[EncodedMethod, ExternalMethod]
                            ) -> MethodClassAnalysis:
    return dx.get_method_analysis(method)


def search_cfg(dx: Analysis, method: MethodClassAnalysis, seen_methods: Set[str]) -> None:
    searched_cfg = False
    if method.full_name not in seen_methods:
        seen_methods.add(method.full_name)
        for _, call, _ in method.get_xref_to():
            for i in dx.find_methods(methodname=call.name, classname=call.class_name):
                searched_cfg = True
                search_cfg(i, set(seen_methods))
    if not searched_cfg:
        print(len(seen_methods))


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


def get_entrypoints(methods: List[MethodClassAnalysis]):
    entrypoints: List[MethodClassAnalysis] = []
    mca:  MethodClassAnalysis
    for mca in methods:
        if mca.name[:2] == "on":
            entrypoints.append(mca)
    return entrypoints


def get_opener_paths(cg: nx.DiGraph, main_mcas: List[MethodClassAnalysis], pair: Pair):
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
                pair: Pair,
                exitpoints: List[EncodedMethod]):
    node: EncodedMethod

    # check if a closer is called directly from the same path
    for node in path:
        for closer in pair.closers:
            try:
                ssp = nx.shortest_simple_paths(cg, node, closer.method)
                if [x for x in ssp]:
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
                  pair: Pair,
                  exitpoints: List[EncodedMethod]):
    open_paths = []
    closed_paths = []
    for path in opener_paths:
        if path_exists(cg, path, pair, exitpoints):
            closed_paths.append(path)
        else:
            open_paths.append(path)
    return open_paths, closed_paths


def print_allocation_path(path: List[EncodedMethod]):
    print("PATH: ")
    for item in path[:-1]:
        print(item.name)
        print("↓")
    print(path[-1])
