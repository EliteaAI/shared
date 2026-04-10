"""
OpenAPI Specification Routes.

Serves OpenAPI specs for registered plugins.

Endpoints:
- GET /shared/openapi/ - Combined spec for all plugins
- GET /shared/openapi/<plugin_name> - Single plugin spec (or "plugins" to list)
"""
import flask

from pylon.core.tools import web

from ..tools.openapi_tools import openapi_registry


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

        # List registered plugins
        if plugin_name == "plugins":
            return {"plugins": openapi_registry.list_plugins()}, 200

        # Single plugin spec
        if plugin_name:
            spec = openapi_registry.get_plugin_spec(plugin_name)
            if not spec:
                return {
                    "error": f"Plugin '{plugin_name}' not found",
                    "available": openapi_registry.list_plugins()
                }, 404
        else:
            # Combined spec
            plugins_filter = flask.request.args.get('plugins')
            if plugins_filter:
                plugins = [p.strip() for p in plugins_filter.split(',')]
            else:
                plugins = None
            spec = openapi_registry.get_combined_spec(plugins)

        # Output format
        if output_format == 'yaml':
            try:
                import yaml
                yaml_content = yaml.dump(spec, default_flow_style=False, sort_keys=False, allow_unicode=True)
                return flask.Response(
                    yaml_content,
                    mimetype='application/x-yaml',
                    headers={'Content-Disposition': 'inline; filename=openapi.yaml'}
                )
            except ImportError:
                return {"error": "YAML not available. Install PyYAML."}, 501

        return spec, 200
