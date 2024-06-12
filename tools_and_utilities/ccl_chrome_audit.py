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

import base64
import json
import pathlib
import re
import sys
import os
import typing
import abc
import sqlite3
import datetime
import win32crypt
import Crypto.Cipher.AES
from ccl_chromium_reader import ccl_chromium_localstorage
from ccl_chromium_reader import ccl_chromium_sessionstorage
from ccl_chromium_reader import ccl_chromium_indexeddb
from ccl_chromium_reader import ccl_chromium_filesystem
from ccl_chromium_reader import ccl_shared_proto_db_downloads
from ccl_chromium_reader import ccl_chromium_cache
from ccl_chromium_reader import ccl_chromium_notifications
from ccl_chromium_reader import ccl_chromium_snss2

sys.stdout.reconfigure(encoding="utf-8")

__version__ = "0.3"
__description__ = "Audits multiple Chromium data stores"
__contact__ = "Alex Caithness"


WINDOWS = False

CHROME_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0)


def chrome_time(microseconds: typing.Optional[int], allow_none=True):
    if microseconds is not None:
        return CHROME_EPOCH + datetime.timedelta(microseconds=microseconds)
    elif allow_none:
        return None
    raise ValueError("microseconds cannot be None")


class AbstractAuditor(abc.ABC):
    def __init__(self, name: str):
        self.name = name

    @property
    @abc.abstractmethod
    def headers(self) -> tuple[str, ...]:
        raise NotImplementedError

    @abc.abstractmethod
    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        raise NotImplementedError


class BookmarksAuditor(AbstractAuditor):
    @property
    def headers(self) -> tuple[str, ...]:
        return "id", "guid", "path", "url", "added time",

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        bookmarks_path = pathlib.Path(profile_root, "Bookmarks")
        if not bookmarks_path.exists():
            return

        with bookmarks_path.open("rt", encoding="utf-8") as f:
            bookmarks = json.load(f)

        def walk_bookmarks(obj: dict, parts: list):
            print(obj)
            for inner in obj["children"]:
                if inner["type"] == "folder":
                    yield from walk_bookmarks(inner, parts + [inner["name"]])
                elif inner["type"] == "url":
                    if domain_re.search(inner["url"]) is not None:
                        yield (
                            inner["id"],
                            inner["guid"],
                            "/".join(parts + [inner["name"]]),
                            inner["url"],
                            chrome_time(int(inner["date_added"]))
                        )
                else:
                    raise ValueError("unexpected bookmark type")

        for key, root in bookmarks["roots"].items():
            if key == "sync_transaction_version":
                continue

            yield from walk_bookmarks(root, [key])

    def __init__(self):
        super().__init__("Bookmarks")


class HistoryAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("History")

    @property
    def headers(self) -> tuple[str, ...]:
        return "id", "url", "title", "timestamp"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        profile_folder = pathlib.Path(profile_root)
        history_path = profile_folder / "History"
        if not history_path.exists():
            return
        conn = sqlite3.connect(history_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
        SELECT 
          visits.id AS "id",
          urls.url AS "url",
          urls.title AS "title",
          visits.visit_time AS "timestamp", 
          visits.visit_duration AS "duration",
          visits.from_visit AS "from_visit",
          visits.transition AS "transition"
        FROM visits
          INNER JOIN urls ON visits.url = urls.id; 
        """)

        for row in cur:
            if domain_re.search(row["url"]) is not None:
                yield (
                    row["id"],
                    row["url"],
                    row["title"],
                    chrome_time(row["timestamp"]),
                )

        conn.close()


class DownloadsHistoryAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Downloads (History)")

    @property
    def headers(self) -> tuple[str, ...]:
        return (
            "id", "guid", "tab url", "tab referrer url", "target path", "total bytes",
            "mime-type", "original mime-type", "start time"
        )

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        profile_folder = pathlib.Path(profile_root)

        history_path = profile_folder / "History"
        if not history_path.exists():
            return

        conn = sqlite3.connect(history_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
                SELECT 
                  downloads.id,
                  downloads.guid,
                  downloads.tab_url,
                  downloads.tab_referrer_url,
                  downloads.target_path,
                  downloads.total_bytes,
                  downloads.mime_type,
                  downloads.original_mime_type,
                  downloads.start_time
                FROM downloads
                """)

        for row in cur:
            if domain_re.search(row["tab_url"]) is not None or domain_re.search(row["tab_referrer_url"]) is not None:
                yield (
                    row["id"],
                    row["guid"],
                    row["tab_url"],
                    row["tab_referrer_url"],
                    row["target_path"],
                    row["total_bytes"],
                    row["mime_type"],
                    row["original_mime_type"],
                    chrome_time(row["start_time"])
                )
        conn.close()


class DownloadsSharedProtoDb(AbstractAuditor):
    def __init__(self):
        super().__init__("Downloads (Shard Proto Db)")

    @property
    def headers(self) -> tuple[str, ...]:
        return (
            "id", "guid", "tab url", "tab referrer url", "target path", "total bytes",
            "mime-type", "original mime-type", "start time"
        )

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        shared_proto_db_folder = pathlib.Path(profile_root) / "shared_proto_db"
        if not shared_proto_db_folder.exists():
            return
        for download in ccl_shared_proto_db_downloads.read_downloads(shared_proto_db_folder):
            if (domain_re.search(download.tab_url or "") is not None or
                    domain_re.search(download.tab_referrer_url or "") is not None):
                yield (
                    download.level_db_seq_no,
                    download.guid,
                    download.tab_url,
                    download.tab_referrer_url,
                    download.target_path,
                    download.total_bytes,
                    download.mime_type,
                    download.original_mime_type,
                    download.start_time
                )


class FaviconAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Favicons")

    @property
    def headers(self) -> tuple[str, ...]:
        return "id", "page_url", "favicon url"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        favicons_path = pathlib.Path(profile_root) / "Favicons"
        if not favicons_path.exists():
            return

        conn = sqlite3.connect(favicons_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute("""
        SELECT 
          icon_mapping.id, 
          icon_mapping.page_url,
          favicons.url
        FROM icon_mapping
        LEFT JOIN favicons ON icon_mapping.icon_id = favicons.id
        """)

        for row in cur:
            if domain_re.search(row["page_url"]) is not None or domain_re.search(row["url"]) is not None:
                yield (
                    row["id"],
                    row["page_url"],
                    row["url"]
                )

        conn.close()


class CacheAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Cache")

    @property
    def headers(self) -> tuple[str, ...]:
        return (
            "key", "request time", "response time", "data stream file type", "data stream file selector",
            "block number", "block count", "data stream external file number")

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern,
              override_path: typing.Optional[typing.Union[os.PathLike, str]] = None) -> typing.Iterator[tuple]:
        cache_folder = override_path or (pathlib.Path(profile_root) / "Cache" / "Cache_Data")
        cache_type = ccl_chromium_cache.guess_cache_class(cache_folder)
        if cache_type == ccl_chromium_cache.ChromiumBlockFileCache:
            with ccl_chromium_cache.ChromiumBlockFileCache(cache_folder) as cache:
                for key, es in cache.items():
                    metas = cache.get_metadata(key)
                    for meta in metas:
                        if domain_re.search(key) is not None:
                            yield (
                                key,
                                meta.request_time,
                                meta.response_time,
                                es.data_addrs[1].file_type,
                                es.data_addrs[1].file_selector,
                                es.data_addrs[1].block_number,
                                es.data_addrs[1].contiguous_blocks,
                                es.data_addrs[1].external_file_number
                            )
        else:
            with ccl_chromium_cache.ChromiumSimpleFileCache(cache_folder) as cache:
                for key in cache.keys():
                    if domain_re.search(key) is not None:
                        metas = zip(cache.get_metadata(key), cache.get_file_for_key(key))
                        for meta, file_name in metas:
                            yield (
                                key,
                                meta.request_time,
                                meta.response_time,
                                file_name
                            )


class CookieAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Cookies")

    @property
    def headers(self) -> tuple[str, ...]:
        return "ID", "Host", "Name", "Value", "Creation Time"

    @staticmethod
    def decrypt_windows_cookie(encryption_key: bytes, cipher_text: bytes):
        cipher = Crypto.Cipher.AES.new(encryption_key, nonce=cipher_text[3:3+12], mode=Crypto.Cipher.AES.MODE_GCM)
        value = cipher.decrypt_and_verify(cipher_text[3+12:-16], cipher_text[-16:])
        return value

    @staticmethod
    def nop(*args):
        return None

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        cookie_path = pathlib.Path(profile_root) / "Cookies"  # old location on windows, still here on some platforms
        if not cookie_path.exists():
            cookie_path = pathlib.Path(profile_root) / "Network" / "Cookies"
        if not cookie_path.exists():
            return

        local_state_path = pathlib.Path(profile_root).parent / "Local State"

        decrypter = self.nop

        if local_state_path.exists():
            if WINDOWS:
                with local_state_path.open("rt", encoding="utf-8") as f:
                    local_state = json.load(f)
                encryption_key = base64.b64decode(local_state['os_crypt']['encrypted_key'])
                encryption_key = encryption_key[5:]
                encryption_key = win32crypt.CryptUnprotectData(encryption_key, None, None, None, 0)[1]
                decrypter = lambda x: self.decrypt_windows_cookie(encryption_key, x)
        else:
            print("Cannot get Local State file to decode cookie values")

        conn = sqlite3.connect(cookie_path)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""SELECT 
                      rowid,
                      cookies.host_key,
                      cookies.name,
                      cookies.value,
                      cookies.encrypted_value,
                      cookies.creation_utc
                    FROM cookies""")

        for row in cur:
            if domain_re.search(row["host_key"]):
                value = row["value"] if row["value"] is not None else decrypter(row["encrypted_value"]).decode("utf-8")
                rowid = row["rowid"] if "rowid" in row else row["creation_utc"]
                yield (
                    rowid,
                    row["host_key"],
                    row["name"],
                    value,
                    chrome_time(row["creation_utc"])
                )

        conn.close()


class LocalStorageAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Local Storage")

    @property
    def headers(self) -> tuple[str, ...]:
        return "id", "storage key", "script key", "value"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        ldb_path = pathlib.Path(profile_root) / "Local Storage" / "leveldb"
        if not ldb_path.exists():
            return

        local_storage =  ccl_chromium_localstorage.LocalStoreDb(ldb_path)
        for storage_key in local_storage.iter_storage_keys():
            if domain_re.search(storage_key) is not None:
                for rec in local_storage.iter_records_for_storage_key(storage_key):
                    yield (
                        rec.leveldb_seq_number,
                        rec.storage_key,
                        rec.script_key,
                        rec.value
                    )

        local_storage.close()


class SessionStorageAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Session Storage")

    @property
    def headers(self) -> tuple[str, ...]:
        return "id", "host", "key", "value"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        ldb_path = pathlib.Path(profile_root) / "Session Storage"
        if not ldb_path.exists():
            return

        session_storage = ccl_chromium_sessionstorage.SessionStoreDb(ldb_path)
        value: typing.Optional[ccl_chromium_sessionstorage.SessionStoreValue] = None
        for host in session_storage.iter_hosts():
            if domain_re.search(host) is not None:
                for ss_key, values in session_storage.get_all_for_host(host).items():
                    for value in values:
                        yield (
                            value.leveldb_sequence_number,
                            host,
                            ss_key,
                            value.value
                        )

        session_storage.close()


class IndexedDbAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("IndexedDb")

    @property
    def headers(self) -> tuple[str, ...]:
        return "id", "origin", "database", "object store", "key", "value"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        idb_root = pathlib.Path(profile_root) / "IndexedDB"
        if not idb_root.exists():
            return

        def bad_deserializer_data_handler(key: ccl_chromium_indexeddb.IdbKey, buffer: bytes):
            print(f"Error reading IndexedDb record {key}", file=sys.stderr)

        for ldb_folder in idb_root.glob("*.leveldb"):
            if domain_re.search(ldb_folder.stem) is not None:
                idb = ccl_chromium_indexeddb.WrappedIndexDB(ldb_folder)
                for database_id in idb.database_ids:
                    database = idb[database_id.dbid_no]
                    for obj_store_name in database.object_store_names:
                        obj_store = database.get_object_store_by_name(obj_store_name)
                        for rec in obj_store.iterate_records(
                                bad_deserializer_data_handler=bad_deserializer_data_handler):
                            yield (
                                rec.sequence_number,
                                database.origin,
                                database.name,
                                obj_store.name,
                                rec.key,
                                rec.value
                            )


class FileSystemAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("FileSystem")

    @property
    def headers(self) -> tuple[str, ...]:
        return "Folder ID", "Sequence Number", "Name", "Data Path", "Storage Type"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        file_system_path = pathlib.Path(profile_root) / "File System"
        if not file_system_path.exists():
            return

        file_system = ccl_chromium_filesystem.FileSystem(file_system_path)
        for origin in file_system.get_origins():
            if domain_re.search(origin):
                for folder in file_system.get_folders_for_origin(origin):
                    origin_storage = file_system.get_storage_for_folder(folder)
                    for file_id, file_info in origin_storage.get_file_listing():
                        yield (
                            file_info.folder_id,
                            file_info.seq_no,
                            file_info.name,
                            file_info.data_path,
                            "Persistent" if file_info.is_persistent else "Temporary"
                        )


class NotificationAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Notifications")

    @property
    def headers(self) -> tuple[str, ...]:
        return "ID", "Origin", "Title", "Body", "Data", "Timestamp"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        notification_path = pathlib.Path(profile_root) / "Platform Notifications"

        if not notification_path.exists():
            return

        with ccl_chromium_notifications.NotificationReader(notification_path) as reader:
            for notification in reader.read_notifications():
                if domain_re.search(notification.origin) is not None:
                    yield (
                        notification.level_db_info.seq_no,
                        notification.origin,
                        json.dumps(notification.title),
                        json.dumps(notification.body),
                        json.dumps(notification.data),
                        notification.timestamp
                    )


class LoginAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Logins")

    @property
    def headers(self) -> tuple[str, ...]:
        return "ID", "database", "origin url", "action url", "username_value"

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        for db_name in ("Login Data", "Login Data For Account"):
            db_path = pathlib.Path(profile_root) / db_name
            if not db_path.exists():
                continue
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()
            cur.execute("""SELECT 
                          rowid,
                          logins.origin_url,
                          logins.action_url,
                          logins.username_value
                        FROM logins""")

            for row in cur:
                if domain_re.search(row["origin_url"]) is not None or domain_re.search(row["action_url"]):
                    yield (
                        row["id"],
                        db_name,
                        row["origin_url"],
                        row["action_url"],
                        row["username_value"]
                    )
            conn.close()


class SnssAuditor(AbstractAuditor):
    def __init__(self):
        super().__init__("Snss")

    @property
    def headers(self) -> tuple[str, ...]:
        return "file", "offset", "index", "timestamp", "title", "url", "original_request_url", "referrer_url",

    def audit(self, profile_root: typing.Union[os.PathLike, str], domain_re: re.Pattern) -> typing.Iterator[tuple]:
        session_folder = pathlib.Path(profile_root) / "Sessions"
        if not session_folder.exists():
            return
        for snss_file in session_folder.iterdir():
            if not snss_file.is_file():
                continue
            if not (snss_file.name.startswith("Session_") or snss_file.name.startswith("Tabs_")):
                continue

            with snss_file.open("rb") as f:
                snss = ccl_chromium_snss2.SnssFile(
                    ccl_chromium_snss2.SnssFileType.Session if snss_file.name.startswith("Session_")
                    else ccl_chromium_snss2.SnssFileType.Tab, f)
                for navigation_entry in snss.iter_session_commands():
                    if not isinstance(navigation_entry, ccl_chromium_snss2.NavigationEntry):
                        continue  # TODO: There may well be other useful session commands to look into later

                    # TODO: add PageState stuff once it's in place in ccl_chromium_snss2
                    yield (
                        snss_file.name,
                        navigation_entry.offset,
                        navigation_entry.index,
                        navigation_entry.timestamp,
                        navigation_entry.title,
                        navigation_entry.url,
                        navigation_entry.original_request_url,
                        navigation_entry.referrer_url,
                    )


AUDITORS: typing.Collection[AbstractAuditor] = (
    BookmarksAuditor(),
    HistoryAuditor(),
    DownloadsHistoryAuditor(),
    DownloadsSharedProtoDb(),
    FaviconAuditor(),
    CacheAuditor(),
    CookieAuditor(),
    LocalStorageAuditor(),
    SessionStorageAuditor(),
    IndexedDbAuditor(),
    FileSystemAuditor(),
    NotificationAuditor(),
    LoginAuditor(),
    SnssAuditor()
)


def main(args):
    profile_folder = pathlib.Path(args[0])
    domain_re = re.compile(args[1])
    cache_folder = None if len(args) < 3 else args[2]

    for auditor in AUDITORS:
        print("-" * 72)
        print(auditor.name)
        print("-" * 72)
        print("\t".join(auditor.headers))

        if isinstance(auditor, CacheAuditor) and cache_folder is not None:
            results = auditor.audit(profile_folder, domain_re, cache_folder)
        else:
            results = auditor.audit(profile_folder, domain_re)

        for result in results:
            print("\t".join(str(x) for x in result))


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"{pathlib.Path(sys.argv[0]).name} <chrome profile folder> <pattern for url matching> [cache folder (for mobile)]")
        exit(1)
    main(sys.argv[1:])
