"""EL-7011, owner request 2026-10-21: an endpoint spec may carry a short `summary` for Swagger."""

import importlib.util
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def openapi_tools():
    path = PLUGIN_ROOT / "tools" / "openapi_tools.py"
    spec = importlib.util.spec_from_file_location("openapi_tools_7011_summary", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _operation(registry, path, method):
    return registry.get_plugin_spec("core")["paths"][path][method]


def test_el7011_register_endpoint_publishes_the_summary(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    registry.register_endpoint(
        plugin_name="core", path="/items", method="get", name="List items",
        description="Answer one page of items.", summary="List items",
    )
    operation = _operation(registry, "/items", "get")
    assert operation["summary"] == "List items"
    assert operation["description"] == "Answer one page of items."


def test_el7011_an_endpoint_without_a_summary_keeps_its_output(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    registry.register_endpoint(plugin_name="core", path="/items", method="get", name="List items")
    operation = _operation(registry, "/items", "get")
    assert "summary" not in operation
    assert list(operation) == ["name", "description", "tags", "parameters", "responses"]


def test_el7011_the_decorator_passes_the_summary_through(openapi_tools):
    class API:
        @openapi_tools.register_openapi(name="Read item", summary="Read an item")
        def get(self, item_id: int, **kwargs):
            return None

    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    openapi_tools.register_api_class(API, "core", "/items", registry)
    assert _operation(registry, "/items", "get")["summary"] == "Read an item"


def test_el7011_the_summary_does_not_change_the_mcp_tool(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    registry.register_endpoint(
        plugin_name="core", path="/items", method="get", name="List items",
        description="Answer one page of items.", summary="List items", mcp_tool=True,
    )
    tool = registry.get_mcp_api_tools(plugins=["core"])[0]
    assert tool["description"] == "Answer one page of items."
    assert "summary" not in tool
