from pathlib import Path

from flask import Response, render_template_string

from pylon.core.tools import web, log

from tools import this


class Route:
    @web.route("/swagger/", methods=["GET"], endpoint="swagger_ui")
    @web.route("/swagger/<string:plugin_name>", methods=["GET"], endpoint="swagger_ui_plugin")
    def swagger(self, plugin_name: str = None):
        if plugin_name:
            spec_url = f"/shared/openapi/{plugin_name}"
            title = f"Elitea - Swagger ({plugin_name.replace('_', ' ').title()})"
        else:
            spec_url = "/shared/openapi/"
            title = "Elitea - Swagger"

        template_path = Path(this.descriptor.path) / "templates" / "swagger.html"
        template_content = template_path.read_text()

        html = render_template_string(
            template_content,
            title=title,
            spec_url=spec_url,
        )

        return Response(html, mimetype='text/html')
