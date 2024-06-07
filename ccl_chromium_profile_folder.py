import sys
import typing
import pathlib
import collections.abc as col_abc

import ccl_chromium_localstorage
import ccl_chromium_sessionstorage

from common import KeySearch, is_keysearch_hit

# TODO: code currently assumes that lazy-loaded stores are present - they might not be, need some kind of guard object?


class ChromiumProfileFolder:
    """
    A class representing a Chrom(e|ium) profile folder with programmatic access to various different data stores.
    Where appropriate, resources are loaded on demand.
    """

    def __init__(self, path: pathlib.Path):
        """
        Constructor

        :param path: Path to the profile folder (usually named Default, Profile 1, Profile 2, etc.)
        """
        if not path.is_dir():
            raise NotADirectoryError(f"Could not find the folder {path}")

        self._path = path

        # Data stores are populated lazily where appropriate
        self._local_storage: typing.Optional[ccl_chromium_localstorage.LocalStoreDb] = None
        self._session_storage: typing.Optional[ccl_chromium_sessionstorage.SessionStoreDb] = None

    def close(self):
        """
        Closes any resources currently open in this profile folder.
        """
        if self._local_storage is not None:
            self._local_storage.close()
        if self._session_storage is not None:
            self._session_storage.close()

    def _lazy_load_localstorage(self):
        if self._local_storage is None:
            self._local_storage = ccl_chromium_localstorage.LocalStoreDb(self._path / "Local Storage" / "leveldb")

    def _lazy_load_sessionstorage(self):
        if self._session_storage is None:
            self._session_storage = ccl_chromium_sessionstorage.SessionStoreDb(self._path / "Session Storage")

    def iter_local_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates the hosts in this profile's local storage
        """
        self._lazy_load_localstorage()
        yield from self._local_storage.iter_storage_keys()

    def iter_local_storage(
            self, storage_key: typing.Optional[KeySearch]=None, script_key: typing.Optional[KeySearch]=None, *,
            include_deletions=False, raise_on_no_result=False
    ) -> col_abc.Iterable[ccl_chromium_localstorage.LocalStorageRecord]:
        """
        Iterates this profile's local storage records

        :param storage_key: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param script_key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool.
        :param include_deletions: if True, records related to deletions will be included
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return: iterable of LocalStorageRecords
        """
        self._lazy_load_localstorage()
        if storage_key is None and script_key is None:
            yield from self._local_storage.iter_all_records(include_deletions=include_deletions)
        elif storage_key is None:
            results = (
                x for x in self._local_storage.iter_all_records(include_deletions=include_deletions)
                if is_keysearch_hit(script_key, x.script_key))
            yielded = False
            for result in results:
                yield result
                yielded = True
            if not yielded and raise_on_no_result:
                raise KeyError(script_key)
        elif script_key is None:
            yield from self._local_storage.iter_records_for_storage_key(
                storage_key, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)
        else:
            yield from self._local_storage.iter_records_for_script_key(
                storage_key, script_key, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)

    def iter_local_storage_with_batches(
            self, storage_key: typing.Optional[KeySearch]=None, script_key: typing.Optional[KeySearch]=None, *,
            include_deletions=False, raise_on_no_result=False
    ) -> col_abc.Iterable[tuple[ccl_chromium_localstorage.LocalStorageRecord, ccl_chromium_localstorage.LocalStorageBatch]]:
        """
        Iterates this profile's local storage records with associated batches where possible.

        :param storage_key: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all hosts are considered.
        :param script_key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all keys are considered.
        :param include_deletions: if True, records related to deletions will be included
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return: iterable of tuples or (LocalStorageRecords, LocalStorageBatch)
        """

        # iter_local_storage lazy loads the localstorage, so we don't need to check ahead of time.
        for rec in self.iter_local_storage(storage_key, script_key,
                                           include_deletions=include_deletions,
                                           raise_on_no_result=raise_on_no_result):
            batch = self._local_storage.find_batch(rec.leveldb_seq_number)
            yield rec, batch

    def iter_session_storage_hosts(self) -> col_abc.Iterable[str]:
        """
        Iterates this profile's session storage hosts
        """
        self._lazy_load_sessionstorage()
        yield from self._session_storage.iter_hosts()

    def iter_session_storage(
            self, host: typing.Optional[KeySearch]=None, key: typing.Optional[KeySearch]=None, *,
            include_deletions=False, raise_on_no_result=True
    ) -> col_abc.Iterable[ccl_chromium_sessionstorage.SessionStoreValue]:
        """
        Iterates this profile's session storage records

        :param host: storage key (host) for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string (each host) and
        returns a bool; or None (the default) in which case all hosts are considered.
        :param key: script defined key for the records. This can be one of: a single string;
        a collection of strings; a regex pattern; a function that takes a string and returns a bool; or
        None (the default) in which case all keys are considered.
        :param include_deletions: if True, records related to deletions will be included
        :param raise_on_no_result: if True (the default) if no matching storage keys are found, raise a KeyError
        (these will have None as values).
        :return: iterable of LocalStorageRecords
        """

        self._lazy_load_sessionstorage()
        if host is None and key is None:
            yield from self._session_storage.iter_all_records(include_deletions=include_deletions, include_orphans=True)
        elif host is None:
            results = (
                rec for
                rec in self._session_storage.iter_all_records(
                include_deletions=include_deletions, include_orphans=True)
                if is_keysearch_hit(key, rec.key)
            )
            yielded = False
            for result in results:
                yield result
                yielded = True
            if not yielded and raise_on_no_result:
                raise KeyError(key)
        elif key is None:
            yield from self._session_storage.iter_records_for_host(
                host, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)
        else:
            yield from self._session_storage.iter_records_for_session_storage_key(
                host, key, include_deletions=include_deletions, raise_on_no_result=raise_on_no_result)

    def __enter__(self) -> "ChromiumProfileFolder":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    @property
    def path(self):
        return self._path

    @property
    def local_storage(self):
        self._lazy_load_localstorage()
        return self._local_storage

    @property
    def session_storage(self):
        self._lazy_load_sessionstorage()
        return self._session_storage

