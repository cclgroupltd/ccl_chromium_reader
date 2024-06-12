import re
import typing
import collections.abc as col_abc


KeySearch = typing.Union[str, re.Pattern, col_abc.Collection[str], col_abc.Callable[[str], bool]]


def is_keysearch_hit(search: KeySearch, value: str):
    if isinstance(search, str):
        return value == search
    elif isinstance(search, re.Pattern):
        return search.search(value) is not None
    elif isinstance(search, col_abc.Collection):
        return value in set(search)
    elif isinstance(search, col_abc.Callable):
        return search(value)
    else:
        raise TypeError(f"Unexpected type: {type(search)} (expects: {KeySearch})")