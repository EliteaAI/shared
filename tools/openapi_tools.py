"""
OpenAPI Tools for Flask-RESTful APIs.

Provides automatic OpenAPI spec generation by decorating API methods.
Works alongside the existing @auth.decorators.check_api() decorator.

Usage in plugin API:
    from ...local_tools import openapi

    class API(APIBase):
        url_params = ['<int:project_id>/<int:config_id>']

        @openapi(
            name="Get Configuration",
            description="Get configuration by ID",
            response_model=ConfigurationDetails,
        )
        @auth.decorators.check_api({...})
        def get(self, project_id: int, config_id: int, **kwargs):
            ...

Usage in plugin module.py:
    from tools import openapi_registry

    def _register_openapi(self):
        from .api import v2 as api_v2
        openapi_registry.register_plugin(
            plugin_name="my_plugin",
            version="1.0.0",
            api_module=api_v2,  # Will auto-scan all API classes in the package
        )
"""
from typing import Any, Callable, Dict, List, Optional, Tuple, Type
from pydantic import BaseModel

from pylon.core.tools import log


def pydantic_to_openapi_schema(model: Type[BaseModel]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Convert Pydantic model to OpenAPI schema.

    Returns:
        Tuple of (schema, definitions) where definitions contains all $defs
        that should be added to components/schemas
    """
    try:
        schema = model.model_json_schema()
    except AttributeError:
        schema = model.schema()

    # Extract $defs to be added at root level
    definitions = {}
    if "$defs" in schema:
        definitions = schema.pop("$defs")

    # Convert internal $ref to OpenAPI format
    schema = _convert_refs_to_components(schema)

    return schema, definitions


def _convert_refs_to_components(obj):
    """Recursively convert $defs references to #/components/schemas/ references."""
    if isinstance(obj, dict):
        if "$ref" in obj:
            # Convert #/$defs/ModelName to #/components/schemas/ModelName
            ref = obj["$ref"]
            if ref.startswith("#/$defs/"):
                obj["$ref"] = ref.replace("#/$defs/", "#/components/schemas/")
        return {k: _convert_refs_to_components(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_convert_refs_to_components(item) for item in obj]
    else:
        return obj


def build_mcp_input_schema(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build MCP inputSchema from OpenAPI endpoint parameters and request body.
    Args: endpoint dictionary with parameters and request_body
    Returns: JSON Schema compatible inputSchema for MCP
    """
    properties = {}
    required = []

    for param in endpoint.get("parameters", []):
        param_name = param.get("name")
        param_in = param.get("in")
        param_required = param.get("required", False)
        param_schema = param.get("schema", {"type": "string"})
        param_description = param.get("description", "")

        if param_in in ("path", "query"):
            properties[param_name] = {
                **param_schema,
                "description": param_description or f"{param_in.title()} parameter: {param_name}",
            }
            if param_required or param_in == "path":
                required.append(param_name)

    request_body = endpoint.get("request_body")
    if request_body is not None:
        try:
            body_schema, _ = pydantic_to_openapi_schema(request_body)
            if "properties" in body_schema:
                for prop_name, prop_schema in body_schema["properties"].items():
                    properties[prop_name] = prop_schema
                if "required" in body_schema:
                    required.extend(body_schema["required"])
        except Exception as e:
            log.warning(f"Failed to convert request body schema: {e}")

    seen = set()
    unique_required = []
    for r in required:
        if r not in seen:
            seen.add(r)
            unique_required.append(r)

    schema = {
        "type": "object",
        "$schema": "http://json-schema.org/draft-07/schema#",
        "properties": properties,
        "additionalProperties": False,
    }

    if unique_required:
        schema["required"] = unique_required

    return schema


class OpenAPIRegistry:
    """
    Global registry for OpenAPI specifications.

    Collects endpoint metadata from decorated methods and generates specs.
    """

    def __init__(self):
        self._plugins: Dict[str, Dict] = {}
        self._endpoints: Dict[str, List[Dict]] = {}

    def register_plugin(
        self,
        plugin_name: str,
        version: str = "1.0.0",
        description: str = "",
        tags: Optional[List[Dict]] = None,
        api_module=None,
        base_path: Optional[str] = None,
    ) -> None:
        """
        Register a plugin for OpenAPI documentation.

        Args:
            plugin_name: Plugin name for grouping
            version: API version string
            description: Plugin description
            tags: Optional list of OpenAPI tag definitions
            api_module: The API package/module to auto-discover endpoints from.
                       If provided, will scan all submodules for API classes.
            base_path: Base URL path for APIs (defaults to /api/v2/{plugin_name})
        """
        self._plugins[plugin_name] = {
            "version": version,
            "description": description,
            "tags": tags or [{"name": plugin_name, "description": description}],
        }
        if plugin_name not in self._endpoints:
            self._endpoints[plugin_name] = []

        # Auto-register APIs from module if provided
        if api_module is not None:
            effective_base_path = base_path or f"/api/v2/{plugin_name}"
            register_api_folder(
                api_package=api_module,
                plugin_name=plugin_name,
                base_path=effective_base_path,
            )

        log.info(f"OpenAPI: Registered plugin '{plugin_name}' v{version}")

    def register_endpoint(
        self,
        plugin_name: str,
        path: str,
        method: str,
        name: str,
        description: str = "",
        tags: Optional[List[str]] = None,
        parameters: Optional[List[Dict]] = None,
        request_body: Optional[Type[BaseModel]] = None,
        response_model: Optional[Type[BaseModel]] = None,
        responses: Optional[Dict] = None,
        security: Optional[List[Dict]] = None,
        deprecated: bool = False,
        mcp_tool: bool = False,
    ) -> None:
        """Register an API endpoint."""
        if plugin_name not in self._endpoints:
            self._endpoints[plugin_name] = []

        # Convert Flask URL params to OpenAPI format
        openapi_path = path.replace("<int:", "{").replace("<string:", "{").replace(">", "}")

        self._endpoints[plugin_name].append({
            "path": openapi_path,
            "method": method.lower(),
            "name": name,
            "description": description,
            "tags": tags or [plugin_name],
            "parameters": parameters or [],
            "request_body": request_body,
            "response_model": response_model,
            "responses": responses,
            "security": security,
            "deprecated": deprecated,
            "mcp_tool": mcp_tool,
        })


    def get_plugin_spec(self, plugin_name: str) -> Dict[str, Any]:
        """Generate OpenAPI spec for a single plugin."""
        if plugin_name not in self._plugins:
            return {}

        plugin_info = self._plugins[plugin_name]

        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": f"{plugin_name.replace('_', ' ').title()} API",
                "version": plugin_info["version"],
                "description": plugin_info["description"],
            },
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "sessionAuth": {
                        "type": "apiKey",
                        "in": "cookie",
                        "name": "session"
                    }
                }
            },
            "security": [{"bearerAuth": []}, {"sessionAuth": []}],
            "tags": plugin_info["tags"],
        }

        self._build_paths(spec, plugin_name)
        return spec

    def get_combined_spec(self, plugins: Optional[List[str]] = None) -> Dict[str, Any]:
        """Generate combined OpenAPI spec for multiple plugins."""
        spec = {
            "openapi": "3.0.3",
            "info": {
                "title": "Elitea Platform API",
                "version": "1.0.0",
                "description": "Combined API specification",
            },
            "paths": {},
            "components": {
                "schemas": {},
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer",
                        "bearerFormat": "JWT"
                    },
                    "sessionAuth": {
                        "type": "apiKey",
                        "in": "cookie",
                        "name": "session"
                    }
                }
            },
            "security": [{"bearerAuth": []}, {"sessionAuth": []}],
            "tags": [],
        }

        target_plugins = plugins or list(self._plugins.keys())

        for plugin_name in target_plugins:
            if plugin_name in self._plugins:
                spec["tags"].extend(self._plugins[plugin_name]["tags"])
                self._build_paths(spec, plugin_name)

        return spec

    def _build_paths(self, spec: Dict, plugin_name: str) -> None:
        """Build paths section for a plugin."""
        for endpoint in self._endpoints.get(plugin_name, []):
            path = endpoint["path"]
            method = endpoint["method"]

            if path not in spec["paths"]:
                spec["paths"][path] = {}

            operation = {
                "name": endpoint["name"],
                "description": endpoint["description"],
                "tags": endpoint["tags"],
                "parameters": endpoint["parameters"],
                "responses": endpoint["responses"] or {
                    "200": {"description": "Success"},
                    "400": {"description": "Bad request"},
                    "401": {"description": "Unauthorized"},
                    "403": {"description": "Forbidden"},
                    "404": {"description": "Not found"},
                    "500": {"description": "Server error"},
                },
            }

            if endpoint["deprecated"]:
                operation["deprecated"] = True

            if endpoint["security"]:
                operation["security"] = endpoint["security"]

            # Request body
            if endpoint["request_body"] and method in ["post", "put", "patch"]:
                model = endpoint["request_body"]
                schema_name = model.__name__
                schema, definitions = pydantic_to_openapi_schema(model)
                spec["components"]["schemas"][schema_name] = schema
                # Add all nested definitions to components/schemas
                spec["components"]["schemas"].update(definitions)

                request_body_content = {
                    "schema": {"$ref": f"#/components/schemas/{schema_name}"}
                }

                if "examples" in schema:
                    examples = schema["examples"]
                    if isinstance(examples, list) and len(examples) > 0:
                        # OpenAPI 3.0 uses 'examples' (plural) with named examples
                        request_body_content["examples"] = {
                            f"example{i+1}": {"value": ex}
                            for i, ex in enumerate(examples)
                        }

                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": request_body_content
                    }
                }

            # Response model
            if endpoint["response_model"]:
                model = endpoint["response_model"]
                schema_name = model.__name__
                schema, definitions = pydantic_to_openapi_schema(model)
                spec["components"]["schemas"][schema_name] = schema
                # Add all nested definitions to components/schemas
                spec["components"]["schemas"].update(definitions)

                response_content = {
                    "schema": {"$ref": f"#/components/schemas/{schema_name}"}
                }

                # Extract examples from schema for better Swagger UI display
                if "examples" in schema:
                    examples = schema["examples"]
                    if isinstance(examples, list) and len(examples) > 0:
                        response_content["examples"] = {
                            f"example{i+1}": {"value": ex}
                            for i, ex in enumerate(examples)
                        }

                operation["responses"]["200"] = {
                    "description": "Success",
                    "content": {
                        "application/json": response_content
                    }
                }

            spec["paths"][path][method] = operation

    def list_plugins(self) -> List[str]:
        """List all registered plugins."""
        return list(self._plugins.keys())

    def get_mcp_api_tools(
        self,
        plugins: Optional[List[str]] = None,
        include_deprecated: bool = False,
    ) -> List[Dict[str, Any]]:
        """
        Returns: list of MCP Tool dictionaries with name, description, and inputSchema
        """
        tools = []
        target_plugins = plugins or list(self._plugins.keys())
        for plugin_name in target_plugins:
            if plugin_name not in self._endpoints:
                continue
            for endpoint in self._endpoints[plugin_name]:
                if endpoint.get("deprecated", False) and not include_deprecated:
                    continue
                if not endpoint.get("mcp_tool", False):
                    continue
                tool = self._endpoint_to_mcp_tool(endpoint)
                if tool:
                    tools.append(tool)
        return tools

    def _endpoint_to_mcp_tool(
        self,
        endpoint: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """
        Convert a single OpenAPI endpoint to MCP Tool format.
        """
        method = endpoint["method"]
        path = endpoint["path"]
        name = endpoint.get("name", "")
        description = endpoint.get("description", "") or name
        path_parts = [p for p in path.split("/") if p and not p.startswith("{")]
        tool_name = _sanitize_mcp_tool_name([method] + path_parts[-2:])

        args_schema = build_mcp_input_schema(endpoint)

        return {
            "label": tool_name,
            "value": tool_name,
            "args_schema": args_schema,
            "description": f"{description}".strip() if description else name,
            "method": method,
            "path": path,
            "parameters": endpoint.get("parameters", []),
        }


def _sanitize_mcp_tool_name(parts: list) -> str:
    """Convert list of parts to camelCase."""
    if not parts:
        return ""

    processed_parts = []
    for i, part in enumerate(parts):
        sub_parts = part.split('_')
        if i == 0:
            processed = sub_parts[0].lower() + ''.join(sp.capitalize() for sp in sub_parts[1:])
        else:
            processed = ''.join(sp.capitalize() for sp in sub_parts)
        processed_parts.append(processed)

    return ''.join(processed_parts)

# Global registry instance
openapi_registry = OpenAPIRegistry()


def register_openapi(
    name: str,
    description: str = "",
    tags: Optional[List[str]] = None,
    parameters: Optional[List[Dict]] = None,
    request_body: Optional[Type[BaseModel]] = None,
    response_model: Optional[Type[BaseModel]] = None,
    responses: Optional[Dict] = None,
    deprecated: bool = False,
    mcp_tool: bool = False,
):
    """
    Decorator to document API methods with OpenAPI metadata.

    Use alongside @auth.decorators.check_api() - this decorator should come FIRST.

    Example:
        @openapi(
            name="Get Configuration",
            description="Retrieves a configuration by ID",
            response_model=ConfigurationDetails,
        )
        @auth.decorators.check_api({...})
        def get(self, project_id: int, config_id: int, **kwargs):
            ...
    """
    def decorator(func: Callable) -> Callable:
        # Store metadata directly on the function - no wrapper needed
        func._openapi = {
            "name": name,
            "description": description,
            "tags": tags or [],
            "parameters": parameters or [],
            "request_body": request_body,
            "response_model": response_model,
            "responses": responses,
            "deprecated": deprecated,
            "mcp_tool": mcp_tool,
        }
        return func

    return decorator


def extract_path_params_from_url(url_params: List[str]) -> List[Dict]:
    """
    Extract OpenAPI parameters from Flask url_params.

    Converts ['<int:project_id>/<int:config_id>'] to OpenAPI parameters.
    Ensures no duplicate parameter names.
    """
    params = []
    seen_names = set()

    if not url_params:
        return params

    for url_param in url_params:
        parts = url_param.split("/")
        for part in parts:
            if part.startswith("<") and part.endswith(">"):
                # Parse <type:name> or <name>
                inner = part[1:-1]
                if ":" in inner:
                    param_type, param_name = inner.split(":", 1)
                else:
                    param_type = "string"
                    param_name = inner

                # Skip if we've already added this parameter
                if param_name in seen_names:
                    continue

                seen_names.add(param_name)
                schema_type = "integer" if param_type == "int" else "string"

                params.append({
                    "name": param_name,
                    "in": "path",
                    "required": True,
                    "schema": {"type": schema_type},
                    "description": param_name.replace("_", " ").title(),
                })

    return params


def register_api_class(
    api_class: type,
    plugin_name: str,
    base_path: str,
    registry: OpenAPIRegistry = None,
) -> None:
    """
    Register all decorated methods from an API class.

    Supports both direct method decoration and mode handler patterns.
    For APIs using mode_handlers, will recursively scan handler classes.

    Args:
        api_class: The API class with @openapi decorated methods
        plugin_name: Plugin name for grouping
        base_path: Base URL path (e.g., "/api/v1/configurations")
        registry: OpenAPI registry (defaults to global)
    """
    if registry is None:
        registry = openapi_registry

    url_params = getattr(api_class, "url_params", [])

    # Build full path and extract params
    if url_params:
        # When using with_modes(), multiple patterns are generated
        # Select the pattern with the MOST parameters (most complete)
        # This ensures we document all possible parameters in OpenAPI
        url_suffix = max(url_params, key=lambda x: x.count('<'))
        full_path = f"{base_path}/{url_suffix}" if url_suffix else base_path
        # Extract path params from the most complete pattern
        path_params = extract_path_params_from_url([url_suffix])
    else:
        full_path = base_path
        path_params = []

    # Convert to OpenAPI format
    full_path = full_path.replace("<int:", "{").replace("<string:", "{").replace(">", "}")

    # Check for mode handlers (e.g., elitea_core pattern)
    mode_handlers = getattr(api_class, "mode_handlers", {})
    classes_to_check = [api_class]  # Start with the API class itself

    # Add all mode handler classes and determine default mode
    default_mode = None
    if mode_handlers:
        classes_to_check.extend(mode_handlers.values())
        # Set default mode to first mode handler key (typically 'prompt_lib')
        default_mode = list(mode_handlers.keys())[0]

    # Check all classes (API class + mode handlers) for decorated methods
    endpoints_registered = 0
    for check_class in classes_to_check:
        for method_name in ["get", "post", "put", "delete", "patch"]:
            method = getattr(check_class, method_name, None)
            if method is None:
                continue

            # Check for _openapi metadata
            openapi_meta = getattr(method, "_openapi", None)
            if openapi_meta is None:
                continue

            # Merge path params with explicit params
            all_params = list(path_params)
            for param in openapi_meta.get("parameters", []):
                # Don't duplicate path params
                if not any(p["name"] == param["name"] for p in all_params):
                    all_params.append(param)

            # Set default value for 'mode' parameter if mode_handlers exist
            if default_mode:
                for param in all_params:
                    if param["name"] == "mode" and param["in"] == "path":
                        param["schema"]["default"] = default_mode
                        param["description"] = f"Mode (default: {default_mode})"
                        break

            registry.register_endpoint(
                plugin_name=plugin_name,
                path=full_path,
                method=method_name,
                name=openapi_meta["name"],
                description=openapi_meta.get("description", ""),
                tags=openapi_meta.get("tags") or [plugin_name],
                parameters=all_params,
                request_body=openapi_meta.get("request_body"),
                response_model=openapi_meta.get("response_model"),
                responses=openapi_meta.get("responses"),
                deprecated=openapi_meta.get("deprecated", False),
                mcp_tool=openapi_meta.get("mcp_tool", False),
            )
            endpoints_registered += 1


def register_api_folder(
    api_package,
    plugin_name: str,
    base_path: str,
    registry: OpenAPIRegistry = None,
) -> int:
    """
    Automatically discover and register all API classes from a package/folder.

    Discovers all Python modules in the package that have an API class with url_params.
    Path is automatically derived: base_path/module_name (e.g., /api/v2/configurations/models)

    Args:
        api_package: The API package (e.g., from .api import v2 as api_v2)
        plugin_name: Plugin name for grouping
        base_path: Base URL path (e.g., "/api/v2/configurations")
        registry: OpenAPI registry (defaults to global)

    Returns:
        Number of API classes registered
    """
    import importlib
    import pkgutil

    if registry is None:
        registry = openapi_registry

    registered_count = 0

    if hasattr(api_package, "__path__"):
        for importer, module_name, is_pkg in pkgutil.iter_modules(api_package.__path__):
            if module_name.startswith("_"):
                continue

            try:
                module = importlib.import_module(f"{api_package.__name__}.{module_name}")

                api_class = getattr(module, "API", None)
                if api_class is None:
                    continue

                if not hasattr(api_class, "url_params"):
                    continue

                # Path is base_path/module_name
                path = f"{base_path}/{module_name}"

                register_api_class(api_class, plugin_name, path, registry)
                registered_count += 1

            except Exception as e:
                log.warning(f"OpenAPI: Failed to register {module_name}: {e}")

    else:
        for name in dir(api_package):
            obj = getattr(api_package, name)
            if isinstance(obj, type) and hasattr(obj, "url_params") and name == "API":
                register_api_class(obj, plugin_name, base_path, registry)
                registered_count += 1

    return registered_count
