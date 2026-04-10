import ast
import codecs
import json
import textwrap
from copy import deepcopy


def _pretty_print_helper(data: dict|list, indent: int = 4):
    if type(data) is list:
        items = enumerate(data)
    elif type(data) is dict:
        items = data.items()
    else:
        return data
    for key, value in items:
        if type(value) in (dict, list):
            value_changed = _pretty_print_helper(value, indent+4)
            data[key] = value_changed
        elif type(value) is str:
            if "Traceback (most recent call last)" in value or value.count('\n') >= 2:
                indent_value = ' '*(indent+4+len(str(key)))
                data[key] = textwrap.indent(f'\n{value}{indent_value}', indent_value)
            elif (value.startswith("{") and value.endswith("}")) or \
                 (value.startswith("[") and value.endswith("]")):
                try:
                    value_changed_to_dict = ast.literal_eval(value) # for single quotes
                except Exception:
                    try:
                        value_changed_to_dict = json.loads(value)
                    except Exception:
                        continue
                value_changed = _pretty_print_helper(value_changed_to_dict, indent+4)
                data[key] = value_changed

    return data


def prettify(data: dict|list):
    object_copy = deepcopy(data)
    object_copy = _pretty_print_helper(object_copy, indent=4)

    return codecs.decode(
        json.dumps(object_copy, indent=4),
        'unicode_escape'
    )
