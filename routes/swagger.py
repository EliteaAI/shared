from pathlib import Path

from flask import Response, render_template_string

from pylon.core.tools import web, log

from tools import this


class Route:
    @web.route("/swagger/", methods=["GET"], endpoint="swagger_ui")
    @web.route("/swagger/<string:plugin_name>", methods=["GET"], endpoint="swagger_ui_plugin")
    def swagger(self, plugin_name: str = None):
        """Serve Swagger UI.

        Args:
            plugin_name: Plugin name for single-plugin spec (optional)
        """
        if plugin_name:
            spec_url = f"/shared/openapi/{plugin_name}"
            title = f"Swagger UI - {plugin_name}"
        else:
            spec_url = "/shared/openapi/"
            title = "Swagger UI - All Plugins"

        # Load template from file
        template_path = Path(this.descriptor.path) / "templates" / "swagger.html"
        template_content = template_path.read_text()

        html = render_template_string(
            template_content,
            title=title,
            spec_url=spec_url,
        )

        return Response(html, mimetype='text/html')
