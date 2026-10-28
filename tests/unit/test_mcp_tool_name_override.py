"""An endpoint may name its MCP tool; without a name the tool keeps the path-derived name."""

import importlib.util
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def openapi_tools():
    path = PLUGIN_ROOT / "tools" / "openapi_tools.py"
    spec = importlib.util.spec_from_file_location("openapi_tools_tool_name", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tools(registry):
    return {tool["value"]: tool for tool in registry.get_mcp_api_tools(plugins=["core"])}


def test_register_endpoint_uses_the_given_tool_name(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    registry.register_endpoint(
        plugin_name="core", path="/schedules/{id}/run", method="post", name="Run",
        mcp_tool=True, tool_name="run_schedule_now",
    )
    tool = _tools(registry)["run_schedule_now"]
    assert tool["label"] == "run_schedule_now"
    assert tool["method"] == "post"


def test_tools_on_one_path_get_distinct_names(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    for method, tool_name in (("get", "get_schedule"), ("delete", "delete_schedule")):
        registry.register_endpoint(
            plugin_name="core", path="/schedules/{id}", method=method, name=tool_name,
            mcp_tool=True, tool_name=tool_name,
        )
    assert set(_tools(registry)) == {"get_schedule", "delete_schedule"}


def test_tool_without_a_name_keeps_the_path_derived_name(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    registry.register_endpoint(
        plugin_name="core", path="/items", method="get", name="List items", mcp_tool=True,
    )
    assert set(_tools(registry)) == {"get_items"}


def test_decorator_passes_the_tool_name_through(openapi_tools):
    class API:
        @openapi_tools.register_openapi(name="List", mcp_tool=True, tool_name="list_schedules")
        def get(self, **kwargs):
            return None

    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    openapi_tools.register_api_class(API, "core", "/schedules", registry)
    assert set(_tools(registry)) == {"list_schedules"}
