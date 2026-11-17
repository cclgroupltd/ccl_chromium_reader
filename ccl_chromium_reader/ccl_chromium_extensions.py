import dataclasses
import os
import pathlib
import json
import re
import typing

from .ccl_chromium_indexeddb import WrappedIndexDB
from .storage_formats import ccl_leveldb


@dataclasses.dataclass
class Extension:
    reader: dataclasses.InitVar["ExtensionsReader"]
    id: str
    name: str
    description: typing.Optional[str]
    version: str
    author: str
    permissions: typing.Tuple[str]

    def __post_init__(self, reader: "ExtensionsReader"):
        self._reader = reader

    def get_state_records(self) -> typing.Iterable["ExtensionStateRecord"]:
        yield from self._reader.get_extension_states(self)

    def get_settings_records(self) -> typing.Iterable["ExtensionSettingRecord"]:
        yield from self._reader.get_local_extension_settings(self)

    def get_indexeddb(self) -> typing.Optional[WrappedIndexDB]:
        return self._reader.get_extension_indexed_db(self)


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
        extensions_dir = self._profile_path / self._EXTENSIONS_FOLDER_NAME

        for ext_dir in extensions_dir.iterdir():
            if ext_dir.is_dir() and self._EXTENSIONS_ID_PATTERN.match(ext_dir.name):
                for version_folder in ext_dir.iterdir():
                    if version_folder.is_dir() and (version_folder / "manifest.json").is_file():
                        with (version_folder / "manifest.json").open("rt", encoding="utf8") as manifest_file:
                            manifest = json.load(manifest_file)

                        manifest_version = manifest["manifest_version"]
                        author = manifest.get("author")
                        description = manifest.get("description")
                        name = manifest["name"]
                        version = manifest.get("version")
                        permissions = tuple(manifest.get("permissions", []))
                        default_locale = manifest.get("default_locale", "_no-default-locale_")

                        # get the default locale and English (US as it's more likely to be present) message files
                        default_messages_path = (version_folder / "_locales" / default_locale / "messages.json")
                        english_messages_path = (version_folder / "_locales" / "en_US" / "messages.json")
                        if default_messages_path.exists():
                            with default_messages_path.open("rt", encoding="utf8") as messages_f:
                                default_messages = json.load(messages_f)
                        else:
                            default_messages = {}

                        if english_messages_path.exists():
                            with english_messages_path.open("rt", encoding="utf8") as messages_f:
                                english_messages = json.load(messages_f)
                        else:
                            english_messages = {}

                        if name_match := self._MSG_KEY_PATTERN.match(name):
                            key = name_match.group(1).lower() if manifest_version < 3 else name_match.group(1)
                            name = default_messages.get(key, {}).get("message")

                        if description_match := self._MSG_KEY_PATTERN.match(description):
                            key = description_match.group(1).lower() if manifest_version < 3 else description_match.group(1)
                            description = english_messages.get(key, {}).get("message")
                            description = description or default_messages.get(key, {}).get("message")

                        self._extensions.append(
                            Extension(self, ext_dir.name, name, description, version, author, permissions))

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


