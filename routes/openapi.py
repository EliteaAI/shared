"""
OpenAPI Specification Routes.

Serves OpenAPI specs for registered plugins.

Endpoints:
- GET /shared/openapi/ - Combined spec for all plugins
- GET /shared/openapi/<plugin_name> - Single plugin spec (or "plugins" to list)
"""
import json

import flask

from pylon.core.tools import web

from ..tools.openapi_tools import openapi_registry

def _json_response(data, status=200):
    """Return an explicit JSON response with correct Content-Type."""
    return flask.Response(
        json.dumps(data),
        status=status,
        mimetype="application/json",
    )


class Route:
    """OpenAPI specification routes."""

    @web.route("/openapi/", methods=["GET"], endpoint="openapi_spec")
    @web.route("/openapi/<string:plugin_name>", methods=["GET"], endpoint="openapi_spec_plugin")
    def openapi(self, plugin_name: str = None):
        """
        Get OpenAPI specification.

        Args:
            plugin_name: Plugin name for single-plugin spec, or "plugins" to list

        Query Parameters:
            format: 'json' (default) or 'yaml'
            plugins: Comma-separated list of plugins (for combined spec)
        """
        output_format = flask.request.args.get('format', 'json').lower()
        full = flask.request.args.get('all', '').lower() == 'true'

        # List registered plugins
        if plugin_name == "plugins":
            return _json_response({"plugins": openapi_registry.list_plugins()})

        # Single plugin spec
        if plugin_name:
            spec = openapi_registry.get_plugin_spec(plugin_name, full=full)
            if not spec:
                return _json_response({
                    "error": f"Plugin '{plugin_name}' not found",
                    "available": openapi_registry.list_plugins()
                }, status=404)
        else:
            # Combined spec
            plugins_filter = flask.request.args.get('plugins')
            if plugins_filter:
                plugins = [p.strip() for p in plugins_filter.split(',')]
            else:
                plugins = None
            spec = openapi_registry.get_combined_spec(plugins, full=full)

        # Output format
        if output_format == 'yaml':
            try:
                import yaml
                yaml_content = yaml.dump(spec, default_flow_style=False, sort_keys=False, allow_unicode=True)
                return flask.Response(
                    yaml_content,
                    mimetype='application/x-yaml',
                    headers={'Content-Disposition': 'inline; filename=openapi.yaml'},
                )
            except ImportError:
                return _json_response({"error": "YAML not available. Install PyYAML."}, status=501)

        return _json_response(spec)
