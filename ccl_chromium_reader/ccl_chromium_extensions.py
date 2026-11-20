import dataclasses
import datetime
import os
import pathlib
import json
import re
import typing
import sqlite3
import urllib.parse
import logging

from .ccl_chromium_indexeddb import WrappedIndexDB
from .ccl_chromium_localstorage import LocalStoreDb, LocalStorageRecord
from .ccl_chromium_sessionstorage import SessionStoreDb, SessionStoreValue
from .ccl_chromium_filesystem import FileSystem, OriginStorage
from .ccl_chromium_cache import ChromiumSimpleFileCache
from .storage_formats import ccl_leveldb

_DEBUG = True

_CHROME_EPOCH = datetime.datetime(1601, 1, 1)

log = logging.getLogger(__name__)


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
        self._referenced_in_locations = set()

    @property
    def referenced_in_locations(self):
        yield from self._referenced_in_locations

    def add_reference_location(self, location: str):
        self._referenced_in_locations.add(location)

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

    def get_filesystem(self) -> typing.Iterable[OriginStorage]:
        return self._reader.get_extension_filesystem(self)

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
    _FILE_SYSTEM_FOLDER_PATH = pathlib.Path("File System")
    _CODE_CACHE_STORAGE_PATH = pathlib.Path("Code Cache", "js")
    _SERVICE_WORKER_SCRIPT_CACHE_PATH = pathlib.Path("Service Worker", "ScriptCache")

    def __init__(
            self, profile_folder_path: typing.Union[os.PathLike, pathlib.Path, str], discover_removed_extensions=True):
        self._profile_path = pathlib.Path(profile_folder_path)
        if not self._profile_path.is_dir():
            raise IOError("profile_folder_path is not a directory or cannot be accessed")

        self._extensions: typing.List[Extension] = []
        self._get_live_extensions()
        if discover_removed_extensions:
            self._discover_removed_extensions()

    @property
    def extensions(self) -> typing.Iterable[Extension]:
        yield from self._extensions

    ## TODO! GET OTHER IDS FROM "Secure Preferences", scan the various other stores for remnents of IDs
    ## QuotaManager could also mention the id,

    def _get_live_extensions(self):
        sec_prefs_path = (self._profile_path / "Secure Preferences")
        if sec_prefs_path.is_file():
            with sec_prefs_path.open("rt", encoding="utf-8") as f:
                sec_prefs = json.load(f)
                extension_settings = sec_prefs.get("extensions", {}).get("settings", {})
                for ext_id, settings in extension_settings.items():
                    manifest = settings.get("manifest", {})
                    new_extension = Extension(
                            self, ext_id, manifest.get("name"), manifest.get("description"), manifest.get("version"),
                            manifest.get("author"), tuple(manifest.get("permissions", [])), True, settings.get("path"),
                            from_chrome_timestamp_str(settings.get("first_install_time")),
                            from_chrome_timestamp_str(settings.get("last_update_time"))
                        )
                    new_extension.add_reference_location("Secure Preferences")
                    self._extensions.append(new_extension)

    def _discover_extensions__extensionstate(self):
        extension_states_path = pathlib.Path(self._profile_path, self._EXTENSION_STATE_FOLDER_NAME)
        ext_ids = set()
        if extension_states_path.is_dir():
            with ccl_leveldb.RawLevelDb(extension_states_path) as ldb:
                for rec in ldb.iterate_records_raw():
                    ext_id, key = rec.user_key.decode("utf8").split(".", 1)
                    ext_ids.add(ext_id)

        return ext_ids

    def _discover_extensions__localstorage(self):
        local_storage_path = pathlib.Path(self._profile_path, self._LOCAL_STORAGE_FOLDER_PATH)
        ext_ids = set()
        if local_storage_path.is_dir():
            with LocalStoreDb(local_storage_path) as lsdb:
                for storage_key in lsdb.iter_storage_keys():
                    if storage_key.startswith("chrome-extension://"):
                        ext_ids.add(storage_key[len("chrome-extension://"):].strip())

        return ext_ids

    def _discover_extensions__sessionstorage(self):
        session_storage_path = pathlib.Path(self._profile_path, self._SESSION_STORAGE_FOLDER_PATH)
        ext_ids = set()
        if session_storage_path.is_dir():
            with SessionStoreDb(session_storage_path) as ssdb:
                for host in ssdb.iter_hosts():
                    if host.startswith("chrome-extension://"):
                        ext_ids.add(host[len("chrome-extension://"):].strip(" /"))

        return ext_ids

    def _discover_extensions__quotamanager(self):
        quotamanager_path = self._profile_path / "WebStorage" / "QuotaManager"
        ext_ids = set()
        if quotamanager_path.is_file():
            with sqlite3.connect(quotamanager_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT storage_key, host FROM buckets;")
                for sk, h in cur:
                    if sk.startswith("chrome-extension://"):
                        ext_ids.add(h)

        return ext_ids

    def _discover_extensions__indexeddb(self):
        indexeddb_path = self._profile_path / self._INDEXEDDB_FOLDER_PATH
        ext_ids = set()
        if indexeddb_path.is_dir():
            for path in indexeddb_path.iterdir():
                if match := re.match(r"chrome-extension_([a-z]{32})_\d.indexeddb", path.name):
                    ext_ids.add(match.group(1))

        return ext_ids

    def _discover_extensions__codecache(self, code_cache_path):
        ext_ids = set()
        if code_cache_path.is_dir():
            cache = ChromiumSimpleFileCache(code_cache_path)
            for ckey in cache.cache_keys():
                if ckey.url.startswith("chrome-extension://"):
                    ext_ids.add(urllib.parse.urlparse(ckey.url).netloc)

        return ext_ids

    def _discover_extensions__favicons(self):
        favicons_path = self._profile_path / "Favicons"
        ext_ids = set()
        if favicons_path.is_file():
            with sqlite3.connect(favicons_path) as conn:
                cur = conn.cursor()
                cur.execute("SELECT url FROM favicons;")
                for url, in cur:
                    if url.startswith("chrome-extension://"):
                        ext_ids.add(urllib.parse.urlparse(url).netloc)

        return ext_ids

    def _discover_extensions__filesystem(self):
        file_system_path = pathlib.Path(self._profile_path, self._FILE_SYSTEM_FOLDER_PATH)
        ext_ids = set()
        if file_system_path.is_dir():
            fs = FileSystem(file_system_path)  # TODO: can cache this as it doesn't hold open files?
            for origin in fs.get_origins():
                if match := re.match(r"chrome-extension_([a-z]{32})_", origin):
                    ext_ids.add(match.group(1))

        return ext_ids

    def _discover_removed_extensions(self):
        # NB - should be called after _get_live_extensions
        known_extensions = dict((e.id, e) for e in self._extensions)
        # places we look:
        # extension state
        # local storage
        # session storage
        # indexeddb (just the folder names)
        # quota manager
        # code cache
        # service worker caches
        # favicons
        # file system api

        # ...anywhere else?..

        # Anyway, this won't be the quickest process.
        discoverers = [
            ("Extension State", self._discover_extensions__extensionstate),
            ("Local Storage", self._discover_extensions__localstorage),
            ("Session Storage", self._discover_extensions__sessionstorage),
            ("IndexedDB", self._discover_extensions__indexeddb),
            ("QuotaManager", self._discover_extensions__quotamanager),
            ("Code Cache", lambda: self._discover_extensions__codecache(self._CODE_CACHE_STORAGE_PATH)),
            ("Service Worker Script Cache",
             lambda: self._discover_extensions__codecache(self._SERVICE_WORKER_SCRIPT_CACHE_PATH)),
            ("Favicons", self._discover_extensions__favicons),
            ("File System API", self._discover_extensions__filesystem)
        ]

        for name, discovery_func in discoverers:
            try:
                discovered_ext_ids = discovery_func()
            except Exception as ex:
                log.warning("Failed to discover extensions from %s)", name, ex, exc_info=True)
                if _DEBUG:
                    raise
                else:
                    continue

            for ext_id in discovered_ext_ids:
                if ext_id in known_extensions:
                    known_extensions[ext_id].add_reference_location(name)
                else:
                    new_extension = Extension(self, ext_id, None, None, None, None, tuple(), False, None, None, None)
                    new_extension.add_reference_location(name)
                    self._extensions.append(new_extension)
                    known_extensions[ext_id] = new_extension

    def get_extension_states(self, extension: Extension) -> typing.Iterable[ExtensionStateRecord]:
        extension_states_path = pathlib.Path(self._profile_path, self._EXTENSION_STATE_FOLDER_NAME)
        if extension_states_path.is_dir():
            with ccl_leveldb.RawLevelDb(extension_states_path) as ldb:
                for rec in ldb.iterate_records_raw():
                    if rec.state == ccl_leveldb.KeyState.Live:
                        ext_id, key = rec.user_key.decode("utf8").split(".", 1)
                        if ext_id == extension.id:
                            yield ExtensionStateRecord(rec, key, json.loads(rec.value.decode("utf8")))

    def get_local_extension_settings(self, extension: Extension):
        extension_settings_path = pathlib.Path(
            self._profile_path, self._EXTENSION_LOCAL_SETTINGS_FOLDER_NAME, extension.id)
        if extension_settings_path.is_dir():
            with ccl_leveldb.RawLevelDb(extension_settings_path) as ldb:
                for rec in ldb.iterate_records_raw():
                    if rec.state == ccl_leveldb.KeyState.Live:
                        yield ExtensionSettingRecord(rec, rec.user_key.decode("utf8"), json.loads(rec.value.decode("utf8")))

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
                    f"chrome-extension://{extension.id}/", raise_on_no_result=False)

    def get_extension_filesystem(self, extension: Extension) -> typing.Iterable[OriginStorage]:
        file_system_path = pathlib.Path(self._profile_path, self._FILE_SYSTEM_FOLDER_PATH)
        if file_system_path.is_dir():
            fs = FileSystem(file_system_path)  # TODO: can cache this as it doesn't hold open files?
            for origin in fs.get_origins():
                if origin.startswith(f"chrome-extension_{extension.id}_"):
                    for folder in fs.get_folders_for_origin(origin):
                        yield fs.get_storage_for_folder(folder)
