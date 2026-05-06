#     Copyright 2026 EPAM Systems
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
import operator
import time
from datetime import datetime
from json import loads
from typing import Union, Optional, Callable, Tuple
from functools import wraps
from urllib.parse import ParseResult, urlparse, urlunparse

from pylon.core.tools import log
from sqlalchemy import and_, SQLColumnExpression
from sqlalchemy.orm import joinedload
from flask_restful import Resource, abort
from flask import request, after_this_request
from werkzeug.utils import secure_filename

from .rpc_tools import RpcMixin

from tools import config as c
from .db import with_project_schema_session
from pylon.core.tools.event import EventManager

def prepare_filter(
        project_id: Optional[int], args: dict, data_model,
        additional_filters: Optional[list] = None,
        rpc_manager: Optional[Callable] = None,
        mode: str = c.DEFAULT_MODE
        ) -> SQLColumnExpression:
    filter_ = []
    try:
        filter_.append(operator.eq(data_model.mode, mode))
    except AttributeError:
        ...

    if mode == 'default':
        if not rpc_manager:
            rpc_manager = RpcMixin().rpc
        project = rpc_manager.call.project_get_or_404(project_id=project_id)
        filter_.append(operator.eq(data_model.project_id, project.id))

    if additional_filters:
        filter_.extend(additional_filters)
        # for key, value in additional_filter.items():
        #     filter_.append(operator.eq(getattr(data_model, key), value))

    if args.get('filter'):
        for key, value in loads(args.get('filter')).items():
            filter_.append(operator.eq(getattr(data_model, key), value))

    filter_ = and_(*filter_)
    return filter_


def get(project_id: Optional[int], args: dict, data_model,
        additional_filters: Optional[list] = None,
        rpc_manager: Optional[Callable] = None,
        mode: str = 'default',
        custom_filter: Optional[SQLColumnExpression] = None,
        joinedload_: Optional[list] = None,
        is_project_schema: bool = False
        ) -> Tuple[int, list]:
    def _calculate_limit(limit: Union[str, int], total: int):
        return total if limit == 'All' or limit == 0 else limit

    limit_ = args.get("limit")
    offset_ = args.get("offset")
    if args.get("sort"):
        sort_rule = getattr(getattr(data_model, args["sort"]), args["order"])()
    else:
        sort_rule = data_model.id.desc()

    if custom_filter is None:
        filter_ = prepare_filter(project_id, args, data_model, additional_filters, rpc_manager, mode)
    else:
        filter_ = custom_filter

    if joinedload_:
        options_ = [joinedload(col) for col in joinedload_]
    else:
        options_ = []

    if is_project_schema:
        with with_project_schema_session(project_id) as session:
            total = session.query(data_model).order_by(sort_rule).filter(filter_).count()
            res = session.query(data_model).filter(
                filter_
            ).options(
                *options_
            ).order_by(
                sort_rule
            ).limit(
                _calculate_limit(limit_, total)
            ).offset(
                offset_
            ).all()

        return total, res

    total = data_model.query.order_by(sort_rule).filter(filter_).count()
    res = data_model.query.filter(
        filter_
    ).options(
        *options_
    ).order_by(
        sort_rule
    ).limit(
        _calculate_limit(limit_, total)
    ).offset(
        offset_
    ).all()

    return total, res


def upload_file_base(bucket: str, data: bytes, file_name: str, client, create_if_not_exists: bool = True) -> None:
    # avoid using this, try MinioClient instead
    if create_if_not_exists:
        if bucket not in client.list_bucket():
            bucket_type = 'system' if bucket in ('tasks', 'tests') else 'local'
            client.create_bucket(bucket=bucket, bucket_type=bucket_type)
    client.upload_file(bucket, data, file_name)


# def upload_file(bucket: str,
#                 f,
#                 project: Union[str, int, 'Project'],
#                 integration_id: Optional[int] = None,
#                 create_if_not_exists: bool = True,
#                 **kwargs) -> None:
#     # avoid using this, try MinioClient instead
#     if isinstance(project, (str, int)):
#         mc = MinioClient.from_project_id(project_id=project,
#                                          integration_id=integration_id,
#                                          is_local=is_local)
#     else:
#         mc = MinioClient(project=project,
#                          integration_id=integration_id,
#                          is_local=is_local)
#
#     upload_file_base(
#         bucket=bucket,
#         data=f.read(),
#         file_name=f.filename,
#         client=mc,
#         create_if_not_exists=create_if_not_exists
#     )
#     try:
#         f.remove()
#     except:
#         pass


# def upload_file_admin(bucket: str,
#                       f,
#                       integration_id: Optional[int] = None,
#                       create_if_not_exists: bool = True,
#                       **kwargs) -> None:
#     # avoid using this, try MinioClient instead
#     upload_file_base(
#         bucket=bucket,
#         data=f.read(),
#         file_name=f.filename,
#         client=MinioClientAdmin(integration_id),
#         create_if_not_exists=create_if_not_exists
#     )
#     try:
#         f.remove()
#     except:
#         pass


class APIBase(Resource):
    mode_handlers = dict()
    url_params = list()

    def proxy_method(self, method: str, mode: str = 'default', **kwargs):
        log.info(f'API call: method: {method=} mode: {mode=} {kwargs=}')
        handler = self.mode_handlers.get(mode)
        if not handler:
            log.warning(f'api handler not found for mode: {mode}')
            abort(404)
        method = getattr(handler(self, mode), method)
        if not method:
            log.warning(f'api method not found for handler: {handler} in mode: {mode}')
            abort(404)
        return method(**kwargs)

    def __init__(self, module):
        self.module = module
        log.debug('APIBase init %s | %s', self.mode_handlers, self.url_params)

    def get(self, **kwargs):
        return self.proxy_method('get', **kwargs)

    def post(self, **kwargs):
        return self.proxy_method('post', **kwargs)

    def put(self, **kwargs):
        return self.proxy_method('put', **kwargs)

    def delete(self, **kwargs):
        return self.proxy_method('delete', **kwargs)

    def patch(self, **kwargs):
        return self.proxy_method('patch', **kwargs)


class APIModeHandler:
    def __init__(self, api: Resource, mode: str = 'default'):
        self._api = api
        self.mode = mode

    def __getattr__(self, item):
        try:
            return self.__dict__[item]
        except KeyError:
            if item in ['get', 'post', 'put', 'delete', 'head', 'options', 'patch']:
                return None
            return getattr(self._api, item)


import urllib.parse


def build_api_url(
        plugin: str, file_name: str, mode: str = 'default',
        api_version: int = 1, trailing_slash: bool = False,
        skip_mode: bool = False
) -> str:
    struct = ['/api', f'v{api_version}', plugin, urllib.parse.quote(file_name)]
    if not skip_mode:
        struct.append(mode)
    url = '/'.join(map(str, struct))
    if trailing_slash:
        url += '/'
    return url


def _get_tracing_context():
    """Get tracing context if tracing plugin is enabled."""
    try:
        from tools import this
        tracing_module = this.for_module('tracing').module
        if tracing_module.enabled:
            tracer = tracing_module.get_tracer()
            return tracer, True
    except Exception:
        pass
    return None, False


def _extract_trace_id():
    """Extract trace ID from request headers."""
    # Try W3C traceparent header first
    traceparent = request.headers.get('traceparent')
    if traceparent:
        try:
            parts = traceparent.split('-')
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass

    # Try custom X-Trace-ID header
    return request.headers.get('X-Trace-ID')


def endpoint_metrics(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        from tools import auth, rpc_tools
        start_time, date_ = time.perf_counter(), datetime.now()

        # Extract trace ID from request
        trace_id = _extract_trace_id()

        req_body = dict()
        if request.content_type == 'application/json':
            try:
                json_data = request.get_json(silent=True)
                if json_data:
                    req_body = dict(json_data)
            except Exception as e:
                log.warning(f'endpoint_metrics body issue: {e}')

        payload = {
            'trace_id': trace_id,  # Include trace ID in metrics
            'project_id': request.view_args.get('project_id', kwargs.get('project_id')),
            'mode': request.view_args.get('mode', kwargs.get('mode')),
            'endpoint': request.endpoint,
            'method': request.method,
            'user': auth.current_user().get("id"),
            'display_name': request.headers.get('X-CARRIER-UID'),
            'date': date_,
            'view_args': request.view_args,
            'query_params': request.args.to_dict(),
            'json': req_body
        }
        if request.files:
            payload['files'] = {k: secure_filename(v.filename) for k, v in request.files.to_dict().items()}

        # Check if tracing is enabled
        tracer, tracing_enabled = _get_tracing_context()

        def modified_function(*args, **kwargs):
            @after_this_request
            def send_metrics(response):
                payload['run_time'] = time.perf_counter() - start_time
                payload['status_code'] = response.status_code
                try:
                    payload['response'] = response.get_data(as_text=True)
                except RuntimeError as e:
                    log.warning(f'send_metrics response.get_data raised {e}')
                    payload['response'] = None
                rpc_tools.EventManagerMixin().event_manager.fire_event('usage_api_monitor', payload)
                return response
            return function(*args, **kwargs)

        # Execute with or without tracing
        if tracing_enabled and tracer:
            from opentelemetry.trace import Status, StatusCode, SpanKind
            from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator

            # Extract parent context from headers
            propagator = TraceContextTextMapPropagator()
            ctx = propagator.extract(carrier=dict(request.headers))

            span_name = f"{request.method} {request.endpoint}"
            with tracer.start_as_current_span(
                span_name,
                context=ctx,
                kind=SpanKind.SERVER,
                attributes={
                    'http.method': request.method,
                    'http.url': request.url,
                    'http.route': request.endpoint,
                    'http.scheme': request.scheme,
                    'http.host': request.host,
                    'project.id': payload.get('project_id'),
                    'user.id': payload.get('user'),
                    'trace.id': trace_id,
                    # Data type for OTEL Collector routing
                    'telemetry.data_type': 'api_traces',
                }
            ) as span:
                try:
                    response = modified_function(*args, **kwargs)
                    status_code = response[1] if isinstance(response, tuple) else 200
                    span.set_attribute('http.status_code', status_code)

                    if status_code >= 400:
                        span.set_status(Status(StatusCode.ERROR, f"HTTP {status_code}"))
                    else:
                        span.set_status(Status(StatusCode.OK))

                    return response
                except Exception as e:
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    span.record_exception(e)
                    raise
        else:
            # No tracing - just run the function
            response = modified_function(*args, **kwargs)
            return response

    return wrapper


def with_modes(url_params: list[str]) -> list:
    params = set()
    for i in url_params:
        if not i.startswith('<string:mode>'):
            if i == '':
                params.add('<string:mode>')
            else:
                params.add(f'<string:mode>/{i}')
        params.add(i)
    return list(params)


def normalize_url(url: str):
    parsed_url = urlparse(str(url))
    normalized_url = urlunparse(
        ParseResult(
            scheme=parsed_url.scheme.lower(),
            netloc=parsed_url.netloc.lower(),
            path=parsed_url.path.rstrip('/'),
            params=parsed_url.params,
            query=parsed_url.query,
            fragment=parsed_url.fragment
        )
    )
    return normalized_url
