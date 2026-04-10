import json
from datetime import datetime
from typing import Any


def formatted_value(obj: Any) -> str:
    if isinstance(obj, datetime):
        return obj.isoformat(timespec='seconds') + 'Z'
    else:
        return str(obj)


def serialize(obj: Any, with_attrs: list | None = None) -> Any:
    # Handle iterable objects
    if isinstance(obj, (list, set, tuple)):
        return [serialize(i, with_attrs=with_attrs) for i in obj]

    # Handle dictionary with potential non-string keys
    if isinstance(obj, dict):
        return {str(k): serialize(v, with_attrs=with_attrs) for k, v in obj.items()}

    # Handle Pydantic v1 and v2 objects
    try:
        # Pydantic v2
        if hasattr(obj, 'model_dump'):
            return serialize(obj.model_dump(mode='json'))
        # Pydantic v1
        if hasattr(obj, 'dict'):
            return serialize(obj.dict())
    except AttributeError:
        pass

    # Handle SQLAlchemy objects
    try:
        if hasattr(obj, '__table__'):
            result = {column.name: getattr(obj, column.name) for column in obj.__table__.columns}
            if with_attrs:
                for attr in with_attrs:
                    result[attr] = getattr(obj, attr)
            return serialize(result)
    except AttributeError:
        pass

    # Handle other plain Python objects
    return json.loads(json.dumps(obj, ensure_ascii=False, default=formatted_value))
