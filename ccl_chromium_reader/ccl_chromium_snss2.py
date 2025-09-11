"""
Copyright 2022, CCL Forensics

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
import enum
import struct
import sys
import os
import pathlib
import datetime
import types
import typing
from .serialization_formats.ccl_easy_chromium_pickle import EasyPickleIterator, EasyPickleException

__version__ = "0.2"
__description__ = "Module for reading Chromium SNSS files"
__contact__ = "Alex Caithness"


class TabRestoreIdType(enum.Enum):
    # components/sessions/core/tab_restore_service_impl.cc
    CommandUpdateTabNavigation = 1
    CommandRestoredEntry = 2
    CommandWindowDeprecated = 3
    CommandSelectedNavigationInTab = 4
    CommandPinnedState = 5
    CommandSetExtensionAppID = 6
    CommandSetWindowAppName = 7
    CommandSetTabUserAgentOverride = 8
    CommandWindow = 9
    CommandSetTabGroupData = 10
    CommandSetTabUserAgentOverride2 = 11
    CommandSetWindowUserTitle = 12
    CommandCreateGroup = 13
    CommandAddTabExtraData = 14

    UnusedCommand = 255


class SessionRestoreIdType(enum.Enum):
    # components/sessions/core/session_service_commands.cc
    CommandSetTabWindow = 0
    CommandSetWindowBounds = 1  # // OBSOLETE Superseded by kCommandSetWindowBounds3.
    CommandSetTabIndexInWindow = 2
    CommandTabNavigationPathPrunedFromBack = 5  # // OBSOLETE: Superseded by kCommandTabNavigationPathPruned instead
    CommandUpdateTabNavigation = 6
    CommandSetSelectedNavigationIndex = 7
    CommandSetSelectedTabInIndex = 8
    CommandSetWindowType = 9
    CommandSetWindowBounds2 = 10  # // OBSOLETE Superseded by kCommandSetWindowBounds3. Except for data migration.
    CommandTabNavigationPathPrunedFromFront = 11  # // Superseded kCommandTabNavigationPathPruned instead
    CommandSetPinnedState = 12
    CommandSetExtensionAppID = 13
    CommandSetWindowBounds3 = 14
    CommandSetWindowAppName = 15
    CommandTabClosed = 16
    CommandWindowClosed = 17
    CommandSetTabUserAgentOverride = 18  # // OBSOLETE: Superseded by kCommandSetTabUserAgentOverride2.
    CommandSessionStorageAssociated = 19
    CommandSetActiveWindow = 20
    CommandLastActiveTime = 21
    CommandSetWindowWorkspace = 22  # // OBSOLETE Superseded by kCommandSetWindowWorkspace2.
    CommandSetWindowWorkspace2 = 23
    CommandTabNavigationPathPruned = 24
    CommandSetTabGroup = 25
    CommandSetTabGroupMetadata = 26  # // OBSOLETE Superseded by kCommandSetTabGroupMetadata2.
    CommandSetTabGroupMetadata2 = 27
    CommandSetTabGuid = 28
    CommandSetTabUserAgentOverride2 = 29
    CommandSetTabData = 30
    CommandSetWindowUserTitle = 31
    CommandSetWindowVisibleOnAllWorkspaces = 32
    CommandAddTabExtraData = 33
    CommandAddWindowExtraData = 34

    # Edge has custom command types. These are what I have seen so far.
    # None of these types appear to be related to browsing data at the moment (typically only a few bytes long).
    EdgeCommandUnknown131 = 131
    EdgeCommandUnknown132 = 132

    UnusedCommand = 255


class PageTransition:
    # ui/base/page_transition_types.h
    _core_mask = 0xff
    _qualifier_mask = 0xffffff00
    _core_transitions = {
            0: "Link",
            1: "Typed",
            2: "AutoBookmark",
            3: "AutoSubframe",
            4: "ManualSubframe",
            5: "Generated",
            6: "AutoToplevel",
            7: "FormSubmit",
            8: "Reload",
            9: "Keyword",
            10: "KeywordGenerated"
    }
    _qualifiers = {
            0x00800000: "Blocked",
            0x01000000: "ForwardBack",
            0x02000000: "FromAddressBar",
            0x04000000: "HomePage",
            0x08000000: "FromApi",
            0x10000000: "ChainStart",
            0x20000000: "ChainEnd",
            0x40000000: "ClientRedirect",
            0x80000000: "ServerRedirect"
    }

    def __init__(self, value):
        self._value = value
        if value < 0:
            # signed to unsigned
            value += (0x80000000 * 2)
        self._core_transition = PageTransition._core_transitions[value & PageTransition._core_mask]
        self._qualifiers = []
        for flag in PageTransition._qualifiers:
            if (value & PageTransition._qualifier_mask) & flag > 0:
                self._qualifiers.append(PageTransition._qualifiers[flag])

    def __str__(self):
        return "; ".join([self._core_transition] + self._qualifiers)

    def __repr__(self):
        return "<ChromeTransition ({0}): {1})>".format(self._value, str(self))

    @property
    def core_transition(self) -> str:
        return self._core_transition

    @property
    def qualifiers(self) -> typing.Iterable[str]:
        yield from self._qualifiers

    @property
    def value(self):
        return self._value


class SnssError(Exception):
    ...


@dataclasses.dataclass(frozen=True)
class SessionCommand:
    offset: int = dataclasses.field(repr=False)
    id_type: typing.Union[SessionRestoreIdType, TabRestoreIdType] = dataclasses.field(repr=False)


@dataclasses.dataclass(frozen=True)
class NavigationEntry(SessionCommand):
    # components/sessions/core/serialized_navigation_entry.cc
    index: int
    url: str
    title: str
    page_state_raw: bytes  # replace with completed PageState object
    transition_type: PageTransition
    has_post_data: typing.Optional[bool] = None
    referrer_url: typing.Optional[str] = None
    original_request_url: typing.Optional[str] = None
    is_overriding_user_agent: typing.Optional[bool] = None
    timestamp: typing.Optional[datetime.datetime] = None
    http_status: typing.Optional[int] = None
    referrer_policy: typing.Optional[int] = None
    extended_map: typing.Optional[types.MappingProxyType] = None
    task_id: typing.Optional[int] = None
    parent_task_id: typing.Optional[int] = None
    root_task_id: typing.Optional[int] = None
    session_id: typing.Optional[int] = None

    @classmethod
    def from_pickle(
            cls, pickle, id_type: typing.Union[SessionRestoreIdType, TabRestoreIdType],
            offset: int, session_id: typing.Optional[int]=None) -> "NavigationEntry":
        index = pickle.read_int32()
        url = pickle.read_string()
        title = pickle.read_string16()
        page_state_length = pickle.read_int32()
        # https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/common/page_state/page_state_serialization.cc;drc=d1e1301c82bef37d30796e2d6098856b851d90a4;l=897
        page_state_raw = pickle.read_aligned(page_state_length)
        transition_type = PageTransition(pickle.read_uint32())

        try:
            type_mask = pickle.read_uint32()
        except EasyPickleException:
            # very old versions of data end here, so we return a partial object here
            return cls(offset, id_type, index, url, title, page_state_raw, transition_type)

        has_post_data = (type_mask & 0x01) > 0
        referrer_url = pickle.read_string()
        _ = pickle.read_int32()  # referrer policy, not used
        original_request_url = pickle.read_string()
        is_overriding_user_agent = pickle.read_bool()
        timestamp = pickle.read_datetime()
        _ = pickle.read_string16()  # search terms, not used
        http_status = pickle.read_int32()
        referrer_policy = pickle.read_int32()

        extended_map_size = pickle.read_int32()
        extended_map = {}
        for _ in range(extended_map_size):
            key = pickle.read_string()
            value = pickle.read_string()
            extended_map[key] = value

        extended_map = types.MappingProxyType(extended_map)

        task_id = None
        parent_task_id = None
        root_task_id = None

        try:
            # these might not exist in older files, so no big deal if we can't get them
            task_id = pickle.read_int64()
            parent_task_id = pickle.read_int64()
            root_task_id = pickle.read_int64()

            child_task_id_count = pickle.read_int32()
            if child_task_id_count != 0:
                raise SnssError("Child tasks should not be present when reading NavigationEntry")
        except EasyPickleException:
            pass

        return cls(
            offset, id_type,
            index, url, title, page_state_raw, transition_type, has_post_data, referrer_url, original_request_url,
            is_overriding_user_agent, timestamp, http_status, referrer_policy, extended_map, task_id, parent_task_id,
            root_task_id, session_id
        )


#0	b'\xdc\x94\xc3nn\x95\xc3n'
@dataclasses.dataclass(frozen=True)
class TabWindow(SessionCommand):
    win_id: int
    tab_id: int

#2  b'n\x95\xc3n\x91\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class TabIndexInWindow(SessionCommand):
    tab_id: int
    index: int

#7  b'm\x95\xc3n\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class NavigationIndex(SessionCommand):
    tab_id: int
    index: int

#8  b'\xdc\x94\xc3n\x90\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class TabInIndex(SessionCommand):
    win_id: int
    index: int

#9  b'\xdc\x94\xc3n\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class WindowType(SessionCommand):
    win_id: int
    index: int

#12  b'n\x95\xc3n\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class PinnedState(SessionCommand):
    tab_id: int
    pinned_state: bool

#14  b'\xb2\x94\xc3n\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x06\x00\x00\xa8\x03\x00\x00\x01\x00\x00\x00
@dataclasses.dataclass(frozen=True)
class WindowBounds3(SessionCommand):
    win_id: int
    x: int
    y: int
    w: int
    h: int
    show_state: int

#15  b'\x08\x00\x00\x00\xdc\x94\xc3n\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class WindowAppName(SessionCommand):
    win_id: int
    app_name: str

#19  assigns a UUID to the integer session id (tabs and windows use sequencial 'session' ids)
# sample data: b',\x00\x00\x00n\x95\xc3n$\x00\x00\x00e8693441_6bfb_4721_8372_d411a3dbabe4'
@dataclasses.dataclass(frozen=True)
class SessionStorageAssociated(SessionCommand):
    id: int
    peristant_id: str

#20 b'\xdc\x94\xc3n'
@dataclasses.dataclass(frozen=True)
class ActiveWindow(SessionCommand):
    win_id: int

#21 ?
@dataclasses.dataclass(frozen=True)
class LastActiveTime(SessionCommand):
    tbd_data: any

#22  b'\x10\x01\x00\x00\xdc\x94\xc3n\x07\x01\x00\x00{"ext_id":"6adb2cb1-7b50-4fe2-96c8-55158dc222de","SHOW_PANEL":true,"SELECTED_PANEL":"PanelNotes","PANEL_WIDTH":755,"SHOW_PANEL_CONTENT":false,"fullScreen":false,"visibleUI":{"bookmarksBar":false,"addressBar":true,"panelToggle":false,"tabs":true,"statusBar":"on"}}\x00'
@dataclasses.dataclass(frozen=True)
class WindowWorkspace(SessionCommand):
    win_id: int
    workspace: str

#23  b'n\x95\xc3n\x00\x00\x00\x009\xc3\x93\xe0L\x99/\x00'
@dataclasses.dataclass(frozen=True)
class WindowWorkspace2(SessionCommand):
    win_id: int
    tbd_data: any

#25  b'0\x00\x00\x00\xdc\x94\xc3n&\x00\x00\x00{8B0E1A65-8E32-47BC-B22F-C8DE2603E783}\x00\x00'
@dataclasses.dataclass(frozen=True)
class TabGroup(SessionCommand):
    id: int
    group_id: str

#27  b'n\x95\xc3n\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class TabGroupMetadata2(SessionCommand):
    id: int
    tbd_data: any

#33  b'\x08\x00\x00\x00\xdc\x94\xc3n\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class TabExtraData(SessionCommand):
    id: int
    extra_data: str

#34  b'\xdc\x94\xc3n\x00\x00\x00\x00'
@dataclasses.dataclass(frozen=True)
class WindowExtraData(SessionCommand):
    id: int
    tbd_data: any


@dataclasses.dataclass(frozen=True)
class UnprocessedEntry(SessionCommand):
    data: any


class SnssFileType(enum.Enum):
    Session = 1
    Tab = 2


class SnssFile:
    def __init__(self, file_type: SnssFileType, stream: typing.BinaryIO):
        # components/sessions/core/command_storage_backend.cc
        self._f = stream
        if file_type == SnssFileType.Session:
            self._id_type = SessionRestoreIdType
        elif file_type == SnssFileType.Tab:
            self._id_type = TabRestoreIdType
        else:
            raise ValueError("file_type is an unknown SnssFileType or is not SnssFileType")

        self._file_type = file_type
        header = self._f.read(8)
        if header[0:4] != b"SNSS":
            raise SnssError(f"Invalid magic; expected SNSS; got {header[0:4]}")
        self._version, = struct.unpack("<I", header[4:8])
        if self._version not in (1, 3):
            raise SnssError(f"Expected version 1 or 3, got version {self._version}")

    @property
    def file_type(self) -> SnssFileType:
        return self._file_type

    def reset(self):
        self._f.seek(8, os.SEEK_SET)

    def _get_next_session_command(self) -> typing.Optional[SessionCommand]:
        # components/sessions/core/command_storage_backend.cc
        start_offset = self._f.tell()
        length_raw = self._f.read(2)
        if not length_raw:
            return None  # eof
        length, = struct.unpack("<H", length_raw)
        data = self._f.read(length)
        if len(data) != length:
            raise ValueError(f"Could not get enough data reading record starting at {start_offset}")
        record_id_type = self._id_type(data[0])

        # components/sessions/core/session_service_commands.cc, components/sessions/core/base_session_service_commands.cc
        # components/sessions/core/tab_restore_service_impl.cc
        if record_id_type in (SessionRestoreIdType.CommandUpdateTabNavigation, TabRestoreIdType.CommandUpdateTabNavigation):  # 6, 1
            with EasyPickleIterator(data[1:]) as pickle:
                session_id = pickle.read_int32()
                nav = NavigationEntry.from_pickle(pickle, record_id_type, start_offset, session_id)
                return nav
        else:
            return proces_cmd_entry(start_offset, record_id_type, data[1:])

    def iter_session_commands(self) -> typing.Iterable[SessionCommand]:
        self.reset()
        while command := self._get_next_session_command():
            yield command


def proces_cmd_entry(start_offset, record_id_type, data):
    if record_id_type is SessionRestoreIdType.CommandSetTabWindow:
        return TabWindow(start_offset, record_id_type, *struct.unpack("II", data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetTabIndexInWindow:
        return TabIndexInWindow(start_offset, record_id_type, *struct.unpack("II", data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetSelectedNavigationIndex:
        return NavigationIndex(start_offset, record_id_type, *struct.unpack("II", data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetSelectedTabInIndex:
        return TabInIndex(start_offset, record_id_type, *struct.unpack("II", data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetWindowType:
        return WindowType(start_offset, record_id_type, *struct.unpack("II", data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetPinnedState:
        (tab_id, pinned_state_int) = struct.unpack("II", data)
        return PinnedState(start_offset, record_id_type, tab_id, bool(pinned_state_int))
    
    elif record_id_type is SessionRestoreIdType.CommandSetWindowBounds3:
        return WindowBounds3(start_offset, record_id_type, *struct.unpack("6I", data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetWindowAppName:
        with EasyPickleIterator(data) as pickle:
            win_id = pickle.read_int32()
            app_name = pickle.read_string()
            return WindowAppName(start_offset, record_id_type, win_id, app_name)
    
    elif record_id_type is SessionRestoreIdType.CommandSessionStorageAssociated:
        with EasyPickleIterator(data) as pickle:
            win_id = pickle.read_int32()
            persistant_id = pickle.read_string()
            return SessionStorageAssociated(start_offset, record_id_type, win_id, persistant_id)
    
    elif record_id_type is SessionRestoreIdType.CommandSetActiveWindow:
        return ActiveWindow(start_offset, record_id_type, *struct.unpack("I", data))
    
    elif record_id_type is SessionRestoreIdType.CommandLastActiveTime:
        return LastActiveTime(start_offset, record_id_type, data)
    
    elif record_id_type is SessionRestoreIdType.CommandSetWindowWorkspace:
        with EasyPickleIterator(data) as pickle:
            win_id = pickle.read_int32()
            workspace = pickle.read_string()
            return WindowWorkspace(start_offset, record_id_type, win_id, workspace)
    
    elif record_id_type is SessionRestoreIdType.CommandSetWindowWorkspace2:
        data_length = len(data) - 4
        f = "I{}s".format(data_length)
        return WindowWorkspace2(start_offset, record_id_type, *struct.unpack(f, data))
    
    elif record_id_type is SessionRestoreIdType.CommandSetTabGroup:
        with EasyPickleIterator(data) as pickle:
            id = pickle.read_int32()
            group_id = pickle.read_string()
            return TabGroup(start_offset, record_id_type, id, group_id)
    
    elif record_id_type is SessionRestoreIdType.CommandSetTabGroupMetadata2:
        data_length = len(data) - 4
        f = "I{}s".format(data_length)
        return TabGroupMetadata2(start_offset, record_id_type, *struct.unpack(f, data))
    
    elif record_id_type is SessionRestoreIdType.CommandAddTabExtraData:
        with EasyPickleIterator(data) as pickle:
            id = pickle.read_int32()
            extra_data = pickle.read_string()
            return TabExtraData(start_offset, record_id_type, id, extra_data)
    
    elif record_id_type is SessionRestoreIdType.CommandAddWindowExtraData:
        data_length = len(data) - 4
        f = "I{}s".format(data_length)
        return WindowExtraData(start_offset, record_id_type, *struct.unpack(f, data))
    
    else:
        print("UnprocessedEntry @ {}".format(start_offset))
        return UnprocessedEntry(start_offset, record_id_type, data)


def main(args):
    in_path = pathlib.Path(args[0])
    if in_path.name.startswith("Session_"):
        file_type = SnssFileType.Session
    elif in_path.name.startswith("Tabs_"):
        file_type = SnssFileType.Tab
    else:
        raise ValueError("File name does not start with Session or Tabs")
    with in_path.open("rb") as f:
        snss_file = SnssFile(file_type, f)
        for command in snss_file.iter_session_commands():
            print(command)


if __name__ == '__main__':
    main(sys.argv[1:])
