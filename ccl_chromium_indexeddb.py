import sys
import os
import pathlib
import ccl_leveldb
import ccl_v8_value_deserializer
import ccl_blink_value_deserializer


class IndexedDb:
    def __init__(self, leveldb_dir: os.PathLike, leveldb_blob_dir: os.PathLike=None):
        self._db = ccl_leveldb.RawLevelDb(leveldb_dir)
        self._blob_dir = leveldb_blob_dir

    def get_metadata(self):
        meta = {}
        for record in self._db.iterate_records_raw(reverse=True):
            if record.key.startswith(b"\x00\x00\x00"):
                print(record)
