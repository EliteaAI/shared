"""Shared file-as-module loader used by both storage test loaders."""
import importlib.util
import sys


def load_file_as_module(name, path, package):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module
