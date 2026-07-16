import re
import typing
import collections.abc as col_abc

from ccl_chromium_reader.profile_folder_protocols import ArtifactLocationProtocol

KeySearch = typing.Union[str, re.Pattern, col_abc.Collection[str], col_abc.Callable[[str], bool]]


class ArtifactLocation(ArtifactLocationProtocol):
    def __init__(self, source_file: str, offset: typing.Optional[int], friendly_string: str):
        self._source_file = source_file
        self._offset = offset
        self._friendly_string = friendly_string

    @property
    def source_file(self) -> str:
        return self._source_file

    @property
    def offset(self) -> typing.Optional[int]:
        return self._offset

    @property
    def friendly_string(self) -> str:
        return self._friendly_string


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