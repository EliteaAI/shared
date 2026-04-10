import re
from functools import wraps
from typing import Optional, Any, Callable
from pylon.core.tools import log

from pydantic.v1 import ValidationError


# variable_pattern = re.compile(r"\s*{{\s*([a-zA-Z0-9_]+)\s*}}\s*")
#
# def _is_special_value(value: Any) -> bool:
#     if isinstance(value, str):
#         if re.fullmatch(variable_pattern, value):
#             return True
#     return False


def handle_exceptions(fn: Callable):

    @wraps(fn)
    def decorated(**kwargs):
        try:
            result = fn(**kwargs)
            return {"ok": True, 'result': result}
        except ValidationError as e:
            valid_errors = []
            for error in e.errors():
                log.info(f"Flow validation error: {error}")
                if error['type'] == "value_error.missing" or "__root__" in error['loc']:
                    valid_errors.append(error)
                    continue

                invalid_value = {**kwargs}
                for loc in error["loc"]:
                    invalid_value = invalid_value[loc]

                # # check for special values
                # if not _is_special_value(invalid_value):
                #     valid_errors.append(error)
                valid_errors.append(error)

            # if valid_errors:
            return {"ok": False, "errors": valid_errors}
            # return {"ok": True} # todo: handle this sh*t
        except Exception as e:
            # log.error(e)
            return {"ok": False, "error": str(e)}

    return decorated


# def handle_pre_run_exceptions(fn):
#     @wraps(fn)
#     def decorated(*args, **kwargs):
#         try:
#             clean_data = fn(*args, **kwargs)
#             return {'ok': True, "result": clean_data.dict()}
#         except ValidationError as e:
#             return {'ok': False, 'error': e.errors()}
#
#     return decorated


class FlowNodes:
    PLACEHOLDER_VARIABLE_REGEX = r"\s*{{\s*([a-zA-Z0-9_]+)\s*}}\s*"
    # variable_pattern = variable_pattern
    variable_pattern = re.compile(PLACEHOLDER_VARIABLE_REGEX)

    _registry = {}

    def __init__(self, module):
        self.module = module

    @staticmethod
    def get_rpc_name(uid: str) -> str:
        return f'flows_node_{uid}'

    @staticmethod
    def get_validator_rpc_name(uid: str) -> str:
        return f'flows_node_validator_{uid}'

    # @staticmethod
    # def get_pre_run_validator_rpc_name(uid: str) -> str:
    #     return f"flows_node_pre_run_validator_{uid}"

    def register(
            self,
            uid: str,
            display_name: Optional[str] = None,
            tooltip: str = '',
            icon_url: Optional[str] = None,
            icon_fa: Optional[str] = None,
            inputs: int = 1,
            outputs: int = 1,
            validation_rpc: Optional[str] = None,
            weight: int = 50,
            **kwargs
    ) -> None:
        structure = {
            'uid': uid,
            'display_name': display_name or uid,
            'tooltip': tooltip,
            'icon_url': icon_url,
            'icon_fa': icon_fa,
            'inputs': inputs,
            'outputs': outputs,
            'validation_rpc': validation_rpc,
            'weight': weight
        }
        structure.update(kwargs)

        # structure['rpc_name'] = self.get_rpc_name(uid)
        log.info('Registering flow <%s>', structure)

        self._registry[uid] = structure

    def register_validator(self, flow_uid: str) -> None:
        log.info('Registering flow validator: <%s> for flow <%s>', self.get_validator_rpc_name(flow_uid), flow_uid)
        try:
            if self._registry[flow_uid]['validation_rpc']:
                log.critical(
                    'Validator already exists for flow %s : %s', flow_uid,
                    self._registry[flow_uid]['validation_rpc']
                )
                raise ValueError(
                    f'Validator already exists for flow {flow_uid} : {self._registry[flow_uid]["validation_rpc"]}'
                )
            self._registry[flow_uid]['validation_rpc'] = self.get_validator_rpc_name(flow_uid)
        except KeyError:
            log.critical(f'Flow {flow_uid} does not exist or is not registered')
            raise KeyError(f'Flow {flow_uid} does not exist or is not registered')

    def flow(
            self,
            uid: str,
            display_name: Optional[str] = None,
            tooltip: str = '',
            icon_url: Optional[str] = None,
            icon_fa: Optional[str] = None,
            inputs: int = 1,
            outputs: int = 1,
            validation_rpc: Optional[str] = None,
            weight: int = 50,
            **kwargs
    ):
        self.register(
            uid=uid,
            display_name=display_name,
            tooltip=tooltip,
            icon_url=icon_url,
            icon_fa=icon_fa,
            inputs=inputs,
            outputs=outputs,
            validation_rpc=validation_rpc,
            weight=weight,
            **kwargs
        )

        def wrapper(func):
            self.module.context.rpc_manager.register_function(
                func,
                name=self.get_rpc_name(uid)
            )
            return func

        return wrapper

    def validator(self, flow_uid: str, **kwargs):
        self.register_validator(flow_uid)

        def wrapper(func):
            self.module.context.rpc_manager.register_function(
                handle_exceptions(func),
                name=self.get_validator_rpc_name(flow_uid)
            )

            # self.module.context.rpc_manager.register_function(
            #     handle_pre_run_exceptions(func),
            #     name=self.get_pre_run_validator_rpc_name(flow_uid)
            # )
            return func

        return wrapper
