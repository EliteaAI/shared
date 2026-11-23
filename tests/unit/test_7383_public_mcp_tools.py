"""#7383: the Elitea Builder catalog uses only the public MCP endpoints (available_to_users), not ?all=true."""

import importlib.util
from pathlib import Path

import pytest


PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def openapi_tools():
    path = PLUGIN_ROOT / "tools" / "openapi_tools.py"
    spec = importlib.util.spec_from_file_location("openapi_tools_7383", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def registry(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("secrets")
    for path, public in (("/secrets/{project_id}", True), ("/credential_grants/{project_id}", False)):
        registry.register_endpoint(plugin_name="secrets", path=path, method="get", name=path, tags=["secrets"],
                                   mcp_tool=True, available_to_users=public)
    return registry


def test_public_only_keeps_the_endpoints_marked_available_to_users(registry):
    tools = registry.get_mcp_api_tools(filter_tags=["secrets"], public_only=True)
    assert [tool["path"] for tool in tools] == ["/secrets/{project_id}"]


def test_without_public_only_every_mcp_endpoint_is_listed(registry):
    tools = registry.get_mcp_api_tools(filter_tags=["secrets"])
    assert len(tools) == 2
