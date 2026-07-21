#!/usr/bin/env python3
"""
Test runner that installs Pylon stubs before pytest.

Usage:
    python tests/run_tests.py [pytest args...]
"""
import sys
import types
from pathlib import Path

PLUGINS_ROOT = Path(__file__).resolve().parent.parent.parent


def install_stubs():
    """Install minimal stubs to prevent ImportError on pylon/tools imports."""

    pylon_stub = types.ModuleType('pylon')
    pylon_core = types.ModuleType('pylon.core')
    pylon_core_tools = types.ModuleType('pylon.core.tools')
    pylon_core_tools_context = types.ModuleType('pylon.core.tools.context')

    class StubLog:
        @staticmethod
        def info(*a, **kw): pass
        @staticmethod
        def debug(*a, **kw): pass
        @staticmethod
        def warning(*a, **kw): pass
        @staticmethod
        def error(*a, **kw): pass
        @staticmethod
        def exception(*a, **kw): pass
        @staticmethod
        def critical(*a, **kw): pass

    class StubContext:
        """Stand-in for pylon.core.tools.context.Context (attribute holder)."""

    pylon_core_tools.log = StubLog()
    pylon_core_tools.module = types.ModuleType('pylon.core.tools.module')
    pylon_core_tools.web = types.ModuleType('pylon.core.tools.web')
    pylon_core_tools_context.Context = StubContext

    sys.modules.setdefault('pylon', pylon_stub)
    sys.modules.setdefault('pylon.core', pylon_core)
    sys.modules.setdefault('pylon.core.tools', pylon_core_tools)
    sys.modules.setdefault('pylon.core.tools.log', pylon_core_tools.log)
    sys.modules.setdefault('pylon.core.tools.module', pylon_core_tools.module)
    sys.modules.setdefault('pylon.core.tools.web', pylon_core_tools.web)
    sys.modules.setdefault('pylon.core.tools.context', pylon_core_tools_context)

    tools_stub = types.ModuleType('tools')
    tools_stub.config = types.ModuleType('tools.config')
    tools_stub.config.SECRETS_MASTER_KEY = None

    class _FakeRpcManager:
        def call(self, *a, **kw):
            raise NotImplementedError

    class _FakeDb:
        def make_session(self, *a, **kw):
            raise NotImplementedError

    class _FakeContext:
        def __init__(self):
            self.rpc_manager = _FakeRpcManager()
            self.db = _FakeDb()  # tests override make_session per-case

    tools_stub.context = _FakeContext()

    sys.modules.setdefault('tools', tools_stub)
    sys.modules.setdefault('tools.config', tools_stub.config)

    if str(PLUGINS_ROOT) not in sys.path:
        sys.path.insert(0, str(PLUGINS_ROOT))


def main():
    install_stubs()

    import pytest
    tests_dir = Path(__file__).parent
    sys.exit(pytest.main([str(tests_dir)] + sys.argv[1:]))


if __name__ == '__main__':
    main()
