import dataclasses
import datetime
import os
import pathlib
import json
import re
import typing

from .ccl_chromium_indexeddb import WrappedIndexDB
from .ccl_chromium_localstorage import LocalStoreDb, LocalStorageRecord
from .ccl_chromium_sessionstorage import SessionStoreDb, SessionStoreValue
from .storage_formats import ccl_leveldb

_CHROME_EPOCH = datetime.datetime(1601, 1, 1)


def from_chrome_timestamp_str(microseconds: str) -> typing.Optional[datetime.datetime]:
    if microseconds is None:
        return None
    return _CHROME_EPOCH + datetime.timedelta(microseconds=int(microseconds))


@dataclasses.dataclass
class Extension:
    reader: dataclasses.InitVar["ExtensionsReader"]
    id: str
    name: typing.Optional[str]
    description: typing.Optional[str]
    version: typing.Optional[str]
    author: typing.Optional[str]
    permissions: typing.Tuple[str]
    is_live: bool
    path: typing.Optional[str]
    first_installed: typing.Optional[datetime.datetime]
    last_updated: typing.Optional[datetime.datetime]

    def __post_init__(self, reader: "ExtensionsReader"):
        self._reader = reader

    def get_state_records(self) -> typing.Iterable["ExtensionStateRecord"]:
        yield from self._reader.get_extension_states(self)

    def get_settings_records(self) -> typing.Iterable["ExtensionSettingRecord"]:
        yield from self._reader.get_local_extension_settings(self)

    def get_indexeddb(self) -> typing.Optional[WrappedIndexDB]:
        return self._reader.get_extension_indexed_db(self)

    def get_localstorage(self) -> typing.Iterable[LocalStorageRecord]:
        return self._reader.get_extension_local_storage(self)

    def get_sessionstorage(self) -> typing.Iterable[SessionStoreValue]:
        return self._reader.get_extension_session_storage(self)


@dataclasses.dataclass
class ExtensionStateRecord:
    original_record: ccl_leveldb.Record
    key: str
    value: typing.Any


@dataclasses.dataclass
class ExtensionSettingRecord:
    original_record: ccl_leveldb.Record
    key: str
    value: typing.Any


class ExtensionsReader:
    _EXTENSIONS_ID_PATTERN = re.compile(r"[a-z]{32}")
    _MSG_KEY_PATTERN = re.compile(r"^__MSG_(.+)__$")
    _EXTENSIONS_FOLDER_NAME = "Extensions"
    _EXTENSION_STATE_FOLDER_NAME = "Extension State"
    _EXTENSION_LOCAL_SETTINGS_FOLDER_NAME = "Local Extension Settings"
    _INDEXEDDB_FOLDER_PATH = "IndexedDB"
    _LOCAL_STORAGE_FOLDER_PATH = pathlib.Path("Local Storage", "leveldb")
    _SESSION_STORAGE_FOLDER_PATH = pathlib.Path("Session Storage")

    def __init__(self, profile_folder_path: typing.Union[os.PathLike, pathlib.Path, str]):
        self._profile_path = pathlib.Path(profile_folder_path)
        if not self._profile_path.is_dir():
            raise IOError("profile_folder_path is not a directory or cannot be accessed")

        self._extensions: typing.List[Extension] = []
        self._get_live_extensions()

    @property
    def extensions(self) -> typing.Iterable[Extension]:
        yield from self._extensions

    ## TODO! GET OTHER IDS FROM "Secure Preferences", scan the various other stores for remnents of IDs
    ## QuotaManager could also mention the,

    def _get_live_extensions(self):
        if (self._profile_path / "Secure Preferences").is_file():
            with (self._profile_path / "Secure Preferences").open("rt", encoding="utf-8") as f:
                sec_prefs = json.load(f)
                extension_settings = sec_prefs.get("extensions", {}).get("settings", {})
                for ext_id, settings in extension_settings.items():
                    manifest = settings.get("manifest", {})
                    self._extensions.append(
                        Extension(
                            self, ext_id, manifest.get("name"), manifest.get("description"), manifest.get("version"),
                            manifest.get("author"), tuple(manifest.get("permissions", [])), True, settings.get("path"),
                            from_chrome_timestamp_str(settings.get("first_install_time")),
                            from_chrome_timestamp_str(settings.get("last_update_time"))
                        )
                    )

    def get_extension_states(self, extension: Extension) -> typing.Iterable[ExtensionStateRecord]:
        extension_states_path = pathlib.Path(self._profile_path, self._EXTENSION_STATE_FOLDER_NAME)
        if extension_states_path.is_dir():
            with ccl_leveldb.RawLevelDb(extension_states_path) as ldb:
                for rec in ldb.iterate_records_raw():
                    if rec.state == ccl_leveldb.KeyState.Live:
                        ext_id, key = rec.key.decode("utf8").split(".", 1)
                        if ext_id == extension.id:
                            yield ExtensionStateRecord(rec, key, json.loads(rec.value.decode("utf8")))

    def get_local_extension_settings(self, extension: Extension):
        extension_settings_path = pathlib.Path(
            self._profile_path, self._EXTENSION_LOCAL_SETTINGS_FOLDER_NAME, extension.id)
        if extension_settings_path.is_dir():
            with ccl_leveldb.RawLevelDb(extension_settings_path) as ldb:
                for rec in ldb.iterate_records_raw():
                    if rec.state == ccl_leveldb.KeyState.Live:
                        yield ExtensionSettingRecord(rec, rec.key.decode("utf8"), json.loads(rec.value.decode("utf8")))

    def get_extension_indexed_db(self, extension: Extension) -> typing.Optional[WrappedIndexDB]:
        extension_idb_path = pathlib.Path(
            self._profile_path, self._INDEXEDDB_FOLDER_PATH,
            f"chrome-extension_{extension.id}_0.indexeddb.leveldb")  # can an extension have a second, third store?
        if extension_idb_path.is_dir():
            blob_path = extension_idb_path.with_suffix(".blob")
            return WrappedIndexDB(
                extension_idb_path,
                blob_path if blob_path.is_dir() else None
            )

        return None

    def get_extension_local_storage(self, extension: Extension) -> typing.Iterable[LocalStorageRecord]:
        local_storage_path = pathlib.Path(self._profile_path, self._LOCAL_STORAGE_FOLDER_PATH)
        if local_storage_path.is_dir():
            with LocalStoreDb(local_storage_path) as lsdb:
                yield from lsdb.iter_records_for_storage_key(
                    f"chrome-extension://{extension.id}", raise_on_no_result=False)

    def get_extension_session_storage(self, extension: Extension) -> typing.Iterable[SessionStoreValue]:
        session_storage_path = pathlib.Path(self._profile_path, self._SESSION_STORAGE_FOLDER_PATH)
        if session_storage_path.is_dir():
            with SessionStoreDb(session_storage_path) as ssdb:
                yield from ssdb.iter_records_for_host(
                    f"chrome-extension://{extension.id}", raise_on_no_result=False)

