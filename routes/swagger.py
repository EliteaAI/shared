from pathlib import Path
import json

import flask
from flask import Response, render_template_string

from pylon.core.tools import web, log

from tools import this
from ..tools.openapi_tools import openapi_registry


class Route:
    @web.route("/swagger/", methods=["GET"], endpoint="swagger_ui")
    @web.route("/swagger/<string:plugin_name>", methods=["GET"], endpoint="swagger_ui_plugin")
    def swagger(self, plugin_name: str = None):
        full_param = flask.request.args.get('all', '')
        full = full_param.lower() == 'true'

        if plugin_name:
            spec_url = f"/shared/openapi/{plugin_name}" + (f"?full={full_param}" if full_param else "")
            title = f"Elitea - Swagger ({plugin_name.replace('_', ' ').title()})"
        else:
            spec_url = "/shared/openapi/" + (f"?full={full_param}" if full_param else "")
            title = "Elitea - Swagger"

        if plugin_name:
            spec = openapi_registry.get_plugin_spec(plugin_name, full=full)
        else:
            spec = openapi_registry.get_combined_spec(full=full)

        template_path = Path(this.descriptor.path) / "templates" / "swagger.html"
        template_content = template_path.read_text()

        html = render_template_string(
            template_content,
            title=title,
            spec_url=spec_url,
            spec_json=json.dumps(spec),
        )

        return Response(html, mimetype='text/html')
