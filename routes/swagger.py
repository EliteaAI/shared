from pathlib import Path
import json

from flask import Response, render_template_string

from pylon.core.tools import web, log

from tools import this
from ..tools.openapi_tools import openapi_registry


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

        if plugin_name:
            spec = openapi_registry.get_plugin_spec(plugin_name)
        else:
            spec = openapi_registry.get_combined_spec()

        template_path = Path(this.descriptor.path) / "templates" / "swagger.html"
        template_content = template_path.read_text()

        html = render_template_string(
            template_content,
            title=title,
            spec_url=spec_url,
            spec_json=json.dumps(spec),
        )

        return Response(html, mimetype='text/html')
