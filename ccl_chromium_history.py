"""
Copyright 2024, CCL Forensics
Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import dataclasses
import datetime
import math
import pathlib
import sqlite3
import enum
import re
import struct
import typing
import collections.abc as colabc

from common import KeySearch

__version__ = "0.1"
__description__ = "Module to access the chrom(e|ium) history database"
__contact__ = "Alex Caithness"

EPOCH = datetime.datetime(1601, 1, 1)


def parse_chromium_time(microseconds: int) -> datetime.datetime:
    return EPOCH + datetime.timedelta(microseconds=microseconds)


def encode_chromium_time(datetime_value: datetime.datetime) -> int:
    return math.floor((datetime_value - EPOCH).total_seconds() * 1000000)


class PageTransitionCoreEnum(enum.IntEnum):
    # chrome/common/page_transition_types.h
    link = 0
    typed = 1
    auto_bookmark = 2
    auto_subframe = 3
    manual_subframe = 4
    generated = 5
    start_page = 6
    form_submit = 7
    reload = 8
    keyword = 9
    keyword_generated = 10


class PageTransitionQualifierEnum(enum.IntFlag):
    blocked = 0x00800000
    forward_back = 0x01000000
    from_address_bar = 0x02000000
    home_page = 0x04000000
    from_api = 0x08000000
    chain_start = 0x10000000
    chain_end = 0x20000000
    client_redirect = 0x40000000
    server_redirect = 0x80000000


@dataclasses.dataclass(frozen=True)
class PageTransition:
    core: PageTransitionCoreEnum
    qualifier: PageTransitionQualifierEnum

    @classmethod
    def from_int(cls, val):
        # database stores values signed, python needs unsigned
        if val < 0:
            val, = struct.unpack(">I", struct.pack(">i", val))

        core = PageTransitionCoreEnum(val & 0xff)
        qual = PageTransitionQualifierEnum(val & 0xffffff00)

        return cls(core, qual)


@dataclasses.dataclass(frozen=True)
class HistoryRecord:
    _owner: "HistoryDatabase" = dataclasses.field(repr=False)
    rec_id: int
    url: str
    title: str
    visit_time: datetime.datetime
    visit_duration: datetime.timedelta
    transition: PageTransition
    from_visit_id: int


class HistoryDatabase:
    _HISTORY_QUERY = """
    SELECT
      "visits"."id",
      "urls"."url",
      "urls"."title",
      "visits"."visit_time",
      "visits"."from_visit",
      "visits"."transition",
      "visits"."visit_duration"
      
    FROM "visits"
      LEFT JOIN "urls" ON "visits"."url" = "urls"."id"
    """

    _WHERE_URL_EQUALS_PREDICATE = """"urls"."url" = ?"""

    _WHERE_URL_REGEX_PREDICATE = """"urls"."url" REGEXP ?"""

    _WHERE_URL_IN_PREDICATE = """"urls"."url" IN ({parameter_question_marks})"""

    _WHERE_VISIT_TIME_EARLIEST = """"visits"."visit_time" >= ?"""

    _WHERE_VISIT_TIME_LATEST = """"visits"."visit_time" <= ?"""

    def __init__(self, db_path: pathlib.Path):
        self._conn = sqlite3.connect(db_path.as_uri() + "?mode=ro", uri=True)
        self._conn.row_factory = sqlite3.Row
        self._conn.create_function("regexp", 2, lambda y, x: 1 if re.search(y, x) is not None else 0)

    def iter_history_records(
            self, url: typing.Optional[KeySearch], *,
            earliest: typing.Optional[datetime.datetime]=None, latest: typing.Optional[datetime.datetime]=None
    ) -> colabc.Iterable[HistoryRecord]:
        cur = self._conn.cursor()

        predicates = []
        parameters = []

        if url is None:
            pass  # no predicate
        elif isinstance(url, str):
            predicates.append(HistoryDatabase._WHERE_URL_EQUALS_PREDICATE)
            parameters.append(url)
        elif isinstance(url, re.Pattern):
            predicates.append(HistoryDatabase._WHERE_URL_REGEX_PREDICATE)
            parameters.append(url.pattern)
        elif isinstance(url, colabc.Collection):
            predicates.append(
                HistoryDatabase._WHERE_URL_IN_PREDICATE.format(
                    parameter_question_marks=",".join("?" for _ in range(len(url)))))
            parameters.extend(url)
        elif isinstance(url, colabc.Callable):
            pass  # we have to call this function across every
        else:
            raise TypeError(f"Unexpected type: {type(url)} (expects: {KeySearch})")

        if earliest is not None:
            predicates.append(HistoryDatabase._WHERE_VISIT_TIME_EARLIEST)
            parameters.append(encode_chromium_time(earliest))

        if latest is not None:
            predicates.append(HistoryDatabase._WHERE_VISIT_TIME_LATEST)
            parameters.append(encode_chromium_time(latest))

        query = HistoryDatabase._HISTORY_QUERY
        if predicates:
            query += f" WHERE {' AND '.join(predicates)}"

        query += ";"

        for row in cur.execute(query, parameters):
            if not isinstance(url, colabc.Callable) or url(row["url"]):
                yield HistoryRecord(
                    self,
                    row["id"],
                    row["url"],
                    row["title"],
                    parse_chromium_time(row["visit_time"]),
                    datetime.timedelta(microseconds=row["visit_duration"]),
                    PageTransition.from_int(row["transition"]),
                    row["from_visit"]
                )

    def close(self):
        self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

