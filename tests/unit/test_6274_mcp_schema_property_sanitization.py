"""Unit tests for MCP schema property name sanitization (EL-6274).

Anthropic rejects the entire tool array if any inputSchema property key falls
outside ^[a-zA-Z0-9_.-]{1,64}$, so bracketed query params must be rewritten.
"""
import importlib.util
import re
from pathlib import Path

import pytest

PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent
ANTHROPIC_PATTERN = re.compile(r"^[a-zA-Z0-9_.-]{1,64}$")


@pytest.fixture(scope="module")
def openapi_tools():
    path = PLUGIN_ROOT / "tools" / "openapi_tools.py"
    spec = importlib.util.spec_from_file_location("openapi_tools_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("name,expected", [
    ("fname", "fname"),
    ("project_id", "project_id"),
    ("api.version-2", "api.version-2"),
    ("fname[]", "fname"),
    ("entities[]", "entities"),
    ("filter[a][b]", "filterab"),
    ("weird name", "weirdname"),
    ("[]", "field"),
])
def test_sanitize_property_name(openapi_tools, name, expected):
    assert openapi_tools.sanitize_property_name(name) == expected


def test_sanitize_truncates_to_64_chars(openapi_tools):
    result = openapi_tools.sanitize_property_name("x" * 200 + "[]")
    assert len(result) == 64
    assert ANTHROPIC_PATTERN.match(result)


def test_overlong_name_with_valid_chars_is_truncated(openapi_tools):
    # The 64-char limit is part of the pattern, so even an all-valid-chars name
    # that is too long must be shortened.
    result = openapi_tools.sanitize_property_name("y" * 100)
    assert result == "y" * 64
    assert ANTHROPIC_PATTERN.match(result)


def test_build_input_schema_sanitizes_query_param(openapi_tools):
    schema = openapi_tools.build_mcp_input_schema({
        "parameters": [
            {"name": "project_id", "in": "path", "schema": {"type": "integer"}},
            {"name": "bucket", "in": "path", "schema": {"type": "string"}},
            {"name": "fname[]", "in": "query",
             "schema": {"type": "array", "items": {"type": "string"}}},
        ],
    })

    assert "fname" in schema["properties"]
    assert "fname[]" not in schema["properties"]
    # Sanitizing must not alter the declared type.
    assert schema["properties"]["fname"]["type"] == "array"
    for key in schema["properties"]:
        assert ANTHROPIC_PATTERN.match(key), key


def test_required_list_uses_sanitized_names(openapi_tools):
    schema = openapi_tools.build_mcp_input_schema({
        "parameters": [
            {"name": "entities[]", "in": "query", "required": True,
             "schema": {"type": "array", "items": {"type": "string"}}},
        ],
    })

    assert schema["required"] == ["entities"]


def test_collision_does_not_overwrite_existing_property(openapi_tools):
    schema = openapi_tools.build_mcp_input_schema({
        "parameters": [
            {"name": "fname", "in": "query", "schema": {"type": "string"}},
            {"name": "fname[]", "in": "query",
             "schema": {"type": "array", "items": {"type": "string"}}},
        ],
    })

    # First declaration wins; the colliding one is dropped, not merged.
    assert schema["properties"]["fname"]["type"] == "string"
