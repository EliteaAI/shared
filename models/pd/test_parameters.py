from typing import Optional, Any, List, get_origin, ForwardRef
from pydantic.v1 import BaseModel, validator, AnyUrl, parse_obj_as


class TestParameter(BaseModel):
    class Config:
        anystr_strip_whitespace = True

    __type_mapping = {
        'url': AnyUrl,
        'urls': List[AnyUrl],
        'list[url]': List[AnyUrl],
        'string': str,
        'number': int,
        'list': list,
        'item': str
    }
    _type_mapping_by_name = dict()
    _required_params = set()

    name: str
    type: Optional[str] = 'string'
    description: Optional[str] = ''
    default: Optional[Any] = ''

    @classmethod
    def get_real_type(cls, type_: str, name: str) -> type:
        if isinstance(type_, type):
            return type_
        if cls._type_mapping_by_name.get(name):
            return cls._type_mapping_by_name.get(name)
        elif cls.__type_mapping.get(type_):
            return cls.__type_mapping.get(type_)
        return str

    @validator('default')
    def convert_default_type(cls, value, values):
        real_type = cls.get_real_type(
            values.get('type'),
            values.get('name')
        )
        value = cls.convert_types(value, real_type)
        return parse_obj_as(Optional[real_type], value)

    @staticmethod
    def convert_types(value, _type, list_delimiter=','):
        _checked_type = get_origin(_type) or _type
        if value is not None:
            if isinstance(value, str):
                value = value.strip()
            if not isinstance(value, list) and _checked_type is list:
                value = [i.strip() for i in str(value).split(list_delimiter) if i]
            elif isinstance(value, list) and _checked_type is not list:
                value = list_delimiter.join(value)
        return value

    @validator('default')
    def validate_required(cls, value, values):
        if values.get('name') in cls._required_params:
            assert value and value != [''], f'{values["name"]} is required'
        return value


class TestParamsBase(BaseModel):
    """
    Base case class.
    Used as a parent class for actual test model
    """
    _required_params = set()
    test_parameters: List[TestParameter]

    @classmethod
    def from_orm(cls, db_obj):
        instance = cls(
            test_parameters=db_obj.test_parameters,
        )
        return instance

    def update(self, other: ForwardRef('TestParamsBase')) -> None:
        test_params_names = set(map(lambda tp: tp.name, other.test_parameters))
        modified_params = other.test_parameters
        for tp in self.test_parameters:
            if tp.name not in test_params_names:
                modified_params.append(tp)
        self.test_parameters = modified_params

    @validator('test_parameters')
    def required_test_param(cls, value):
        lacking_values = cls._required_params.difference(set(i.name for i in value))
        assert not lacking_values, f'The following parameters are required: {", ".join(lacking_values)}'
        return value


# TestParamsBase.update_forward_refs()
