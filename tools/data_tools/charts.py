import random
from typing import List, Generator


def color_gen(n: int, max_step: int = 51) -> Generator:
    if n <= 0:
        yield 0, 0, 0
    else:
        color = random.choices(range(256), k=3)
        # step = (256 * 256 * 256) // n % 256
        # step = max(step, 1)
        # step = min(step, max_step)
        step = max_step
        for _ in range(n):
            indexes_to_change = random.choices(range(3), k=2)
            for idx in indexes_to_change:
                color[idx] += step
                color[idx] %= 256
            yield tuple(color)


def get_colors(n: int, shuffle: bool = False, strict: bool = False, max_step: int = 51) -> List[tuple]:
    """
    returns list of colors with size of n
    :param n: number of colors to return
    :param shuffle: shuffle final list (default: False). Works only if strict == False
    :param strict: try to make list of all random colors, if certain attempts to generate random color failed
    then duplicates the rest part. Works best with smaller Ns, result is shuffled
    :param max_step: maximum step to get next color. Step depends on N. Smaller numbers make colors similar,
    big numbers make no sense
    :return: list of tuples of r,g,b
    """
    if n <= 0:
        return [(0, 0, 0)]
    if strict:
        result = set()
        max_attempts = 13
        attempts = max_attempts
        while len(result) < n and attempts > 0:
            prev_len = len(result)
            result.add(tuple(random.choices(range(256), k=3)))
            if len(result) == prev_len:
                attempts -= 1
            else:
                attempts = max_attempts
        result = list(result)
        result.extend(random.choices(result, k=n - len(result)))
    else:
        result = list(color_gen(n=n, max_step=max_step))
        if shuffle:
            random.shuffle(result)
    return list(result)
