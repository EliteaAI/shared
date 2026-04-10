from datetime import datetime
from typing import Union

from pylon.core.tools import log
from bs4 import BeautifulSoup
import json


def tag_format(tags):
    badge_classes = {
        'badge-primary': 0,
        'badge-secondary': 0,
        'badge-success': 0,
        'badge-danger': 0,
        'badge-warning': 0,
        'badge-info': 0,
        'badge-light': 0,
        'badge-dark': 0,
    }
    tag_badge_mapping = dict()

    result = []
    for tag in tags:
        chosen_class = tag_badge_mapping.get(tag, sorted(badge_classes, key=badge_classes.get)[0])
        badge_classes[chosen_class] += 1
        tag_badge_mapping[tag] = chosen_class
        result.append(f'<span class="badge mr-1 {chosen_class}">{tag}</span>')

    return ''.join(result)


def extract_tags(markup, tags: list = ['script', 'style']):
    soup = BeautifulSoup(markup, 'html.parser')
    extracted = [s.extract() for s in soup(tags)]
    return str(soup), ''.join(map(str, extracted))


def map_method_call(lst: list, method_name: str):
    log.warning('Calling method %s on %s', method_name, lst)
    return [getattr(i, method_name)() for i in lst]


def list_pd_to_json(lst: list):
    return json.dumps([i.dict() for i in lst], ensure_ascii=False)


def pretty_json(data: Union[dict, str], indent: int = 2):
    d = data
    if isinstance(data, str):
        d = json.loads(data)
    try:
        return json.dumps(d, ensure_ascii=False, indent=indent)
    except Exception as e:
        log.warning('pretty_json Error %s', e)
    return ''


def humanize_timestamp(timestamp: str):
    dt = datetime.fromtimestamp(int(timestamp)/1000.0)
    return format_datetime(dt)


def format_datetime(dt: datetime):
    return dt.strftime("%d.%m.%Y, %H:%M:%S")
