"""MCP tools may expose a narrower body than the public HTTP endpoint."""

import importlib.util
from pathlib import Path

import pytest
from pydantic import BaseModel


PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def openapi_tools():
    path = PLUGIN_ROOT / "tools" / "openapi_tools.py"
    spec = importlib.util.spec_from_file_location("openapi_tools_6528", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class PublicVersionUpdate(BaseModel):
    instructions: str = ""
    welcome_message: str | None = None


class McpVersionUpdate(BaseModel):
    welcome_message: str | None = None


def test_mcp_request_body_does_not_change_public_openapi_schema(openapi_tools):
    registry = openapi_tools.OpenAPIRegistry()
    registry.register_plugin("core")
    registry.register_endpoint(
        plugin_name="core",
        path="/version/{version_id}",
        method="put",
        name="Update version",
        parameters=[{
            "name": "version_id",
            "in": "path",
            "required": True,
            "schema": {"type": "integer"},
        }],
        request_body=PublicVersionUpdate,
        mcp_request_body=McpVersionUpdate,
        mcp_tool=True,
    )

    tool = registry.get_mcp_api_tools(plugins=["core"])[0]
    assert set(tool["args_schema"]["properties"]) == {
        "version_id", "welcome_message",
    }
    assert "instructions" not in tool["args_schema"]["properties"]

    public_schema = registry.get_plugin_spec("core")["components"]["schemas"]
    assert "instructions" in public_schema["PublicVersionUpdate"]["properties"]
    assert "McpVersionUpdate" not in public_schema
