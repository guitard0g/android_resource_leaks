from typing import Union

from androguard.core.analysis.analysis import (
    ClassAnalysis,
    ExternalMethod,
    MethodAnalysis,
    MethodClassAnalysis,
)
from androguard.core.bytecodes.dvm import EncodedMethod


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


def get_MethodAnalysis(method: Union[EncodedMethod, ExternalMethod]) -> MethodAnalysis:
    return dx.get_method(method)


def get_MethodClassAnalysis(
        method: Union[EncodedMethod, ExternalMethod]
) -> MethodClassAnalysis:
    return dx.get_method_analysis(method)


def search_cfg(method: MethodClassAnalysis) -> None:
    searched_cfg = False
    if method.full_name not in seen_methods:
        seen_methods.add(method.full_name)
        for _, call, _ in method.get_xref_to():
            for i in dx.find_methods(methodname=call.name, classname=call.class_name):
                searched_cfg = True
                search_cfg(i, set(seen_methods))
    if not searched_cfg:
        print(len(seen_methods))


def add_cg_link(m1, m2):
    if m1 and m2:
        cg.add_edge(m1, m2)


def link_to_exit_methods(m: EncodedMethod):
    for method in exit_methods:
        add_cg_link(m, method)


class ResourceLifecycle(object):
    def __init__(
            self,
            source=None,
            allocator=None,
            deallocator=None,
            allocation_caller=None,
            allocation_path=None,
            deallocation_path=None,
    ):
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
                break
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
        return (
                str(self.source.name)
                + " -> "
                + str(self.allocator.name)
                + " -> "
                + str(self.deallocator.name)
                + ", Branch: "
                + str(self.allocation_caller.name)
                + " -> "
                + str(self.allocator.name)
        )
