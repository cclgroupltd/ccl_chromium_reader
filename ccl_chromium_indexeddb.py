# import sys
import struct
import os
import pathlib
import io
import enum
import datetime
import dataclasses
import types
import typing
import ccl_leveldb
import ccl_v8_value_deserializer
import ccl_blink_value_deserializer


def _read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False):
    # this only outputs unsigned
    i = 0
    result = 0
    underlying_bytes = []
    limit = 5 if is_google_32bit else 10
    while i < limit:
        raw = stream.read(1)
        if len(raw) < 1:
            return None
        tmp, = raw
        underlying_bytes.append(tmp)
        result |= ((tmp & 0x7f) << (i * 7))

        if (tmp & 0x80) == 0:
            break
        i += 1
    return result, bytes(underlying_bytes)


def read_le_varint(stream: typing.BinaryIO, *, is_google_32bit=False):
    x = _read_le_varint(stream, is_google_32bit=is_google_32bit)
    if x is None:
        return None
    else:
        return x[0]


def _le_varint_from_bytes(data: bytes):
    with io.BytesIO(data) as buff:
        return _read_le_varint(buff)


def le_varint_from_bytes(data: bytes):
    with io.BytesIO(data) as buff:
        return read_le_varint(buff)


class IdbKeyType(enum.IntEnum):
    Null = 0
    String = 1
    Date = 2
    Number = 3
    Array = 4
    MinKey = 5
    Binary = 6


class IdbKey:
    # See: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_leveldb_coding.cc
    def __init__(self, buffer: bytes):
        self.raw_key = buffer
        self.key_type = IdbKeyType(buffer[0])
        raw_key = buffer[1:]

        if self.key_type == IdbKeyType.Null:
            self.value = None
            self._raw_length = 1
        elif self.key_type == IdbKeyType.String:
            str_len, varint_raw = _le_varint_from_bytes(raw_key)
            self.value = raw_key[len(varint_raw):len(varint_raw) + str_len * 2].decode("utf-16-be")
            self._raw_length = 1 + len(varint_raw) + str_len * 2
        elif self.key_type == IdbKeyType.Date:
            ts, = struct.unpack("<d", raw_key[0:8])
            self.value = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ts)
            self._raw_length = 9
        elif self.key_type == IdbKeyType.Number:
            self.value = struct.unpack("<d", raw_key[0:8])[0]
            self._raw_length = 9
        elif self.key_type == IdbKeyType.Array:
            array_count, varint_raw = _le_varint_from_bytes(raw_key)
            raw_key = raw_key[len(varint_raw):]
            self.value = []
            self._raw_length = 1 + len(varint_raw)
            for i in range(array_count):
                key = IdbKey(raw_key)
                raw_key = raw_key[key._raw_length:]
                self._raw_length += key._raw_length
                self.value.append(key)
            self.value = tuple(self.value)
        elif self.key_type == IdbKeyType.MinKey:
            # TODO: not sure what this actually implies, the code doesn't store a value
            self.value = None
            self._raw_length = 1
        elif self.key_type == IdbKeyType.Binary:
            str_len, varint_raw = _le_varint_from_bytes(raw_key)
            self.value = raw_key[len(varint_raw):len(varint_raw) + str_len * 2]
            self._raw_length = 1 + len(varint_raw) + str_len * 2
        else:
            raise ValueError()  # Shouldn't happen

    def __repr__(self):
        return f"<IdbKey {self.value}>"

    def __str__(self):
        return self.__repr__()


class IndexedDBExternalObjectType(enum.IntEnum):
    # see: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_external_object.h
    Blob = 0
    File = 1
    NativeFileSystemHandle = 2


class IndexedDBExternalObject:
    # see: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/indexed_db_backing_store.cc
    # for encoding.

    def __init__(self, object_type: IndexedDBExternalObjectType, blob_number: typing.Optional[int],
                 mime_type: typing.Optional[str], size: typing.Optional[int],
                 file_name: typing.Optional[str], last_modified: typing.Optional[datetime.datetime],
                 native_file_token: typing.Optional):
        self.object_type = object_type
        self.blob_number = blob_number
        self.mime_type = mime_type
        self.size = size
        self.file_name = file_name
        self.last_modified = last_modified
        self.native_file_token = native_file_token

    @classmethod
    def from_stream(cls, stream: typing.BinaryIO):
        blob_type = IndexedDBExternalObjectType(stream.read(1)[0])
        if blob_type in (IndexedDBExternalObjectType.Blob, IndexedDBExternalObjectType.File):
            blob_number = read_le_varint(stream)
            mime_type_length = read_le_varint(stream)
            mime_type = stream.read(mime_type_length * 2).decode("utf-16-be")
            data_size = read_le_varint(stream)

            if blob_type == IndexedDBExternalObjectType.File:
                file_name_length = read_le_varint(stream)
                file_name = stream.read(file_name_length * 2).decode("utf-16-be")
                x, x_raw = _read_le_varint(stream)
                last_modified_td = datetime.timedelta(microseconds=x)
                last_modified = datetime.datetime(1601, 1, 1) + last_modified_td
                return cls(blob_type, blob_number, mime_type, data_size, file_name,
                           last_modified, None)
            else:
                return cls(blob_type, blob_number, mime_type, data_size, None, None, None)
        else:
            raise NotImplementedError()


@dataclasses.dataclass(frozen=True)
class DatabaseId:
    dbid_no: int
    origin: str
    name: str


class GlobalMetadata:
    def __init__(self, raw_meta_dict: dict):
        # TODO: more of these meta types if required
        self.backing_store_schema_version = None
        if raw_schema_version := raw_meta_dict.get("\x00\x00\x00\x00\x00"):
            self.backing_store_schema_version = le_varint_from_bytes(raw_schema_version)

        self.max_allocated_db_id = None
        if raw_max_db_id := raw_meta_dict.get("\x00\x00\x00\x00\x01"):
            self.max_allocated_db_id = le_varint_from_bytes(raw_max_db_id)

        database_ids_raw = (raw_meta_dict[x] for x in raw_meta_dict
                            if x.startswith(b"\x00\x00\x00\x00\xc9"))

        dbids = []
        for dbid_rec in database_ids_raw:
            with io.BytesIO(dbid_rec.key[5:]) as buff:
                origin_length = read_le_varint(buff)
                origin = buff.read(origin_length * 2).decode("utf-16-be")
                db_name_length = read_le_varint(buff)
                db_name = buff.read(db_name_length * 2).decode("utf-16-be")

            db_id_no = le_varint_from_bytes(dbid_rec.value)

            dbids.append(DatabaseId(db_id_no, origin, db_name))

        self.db_ids = tuple(dbids)


class DatabaseMetadataType(enum.IntEnum):
    OriginName = 0  # String
    DatabaseName = 1  # String
    IdbVersionString = 2  # String (and obsolete)
    MaximumObjectStoreId = 3  # Int
    IdbVersion = 4  # Varint
    BlobNumberGeneratorCurrentNumer = 5  # Varint


class DatabaseMetadata:
    def __init__(self, raw_meta: dict):
        self._metas = types.MappingProxyType(raw_meta)

    def get_meta(self, db_id: int, meta_type: DatabaseMetadataType):
        record = self._metas.get((db_id, meta_type))
        if not record:
            return None

        if meta_type == DatabaseMetadataType.MaximumObjectStoreId:
            return le_varint_from_bytes(record.value)

        # TODO
        raise NotImplementedError()


class ObjectStoreMetadataType(enum.IntEnum):
    StoreName = 0  # String
    KeyPath = 1  # IDBKeyPath
    AutoIncrementFlag = 2  # Bool
    IsEvictable = 3  # Bool (and obsolete apparently)
    LastVersionNumber = 4  # Int
    MaximumAllocatedIndexId = 5  # Int
    HasKeyPathFlag = 6  # Bool (and obsolete apparently)
    KeygeneratorCurrentNumber = 7  # Int


class ObjectStoreMetadata:
    # All metadata fields are prefaced by a 0x00 byte
    def __init__(self, raw_meta: dict):
        self._metas = types.MappingProxyType(raw_meta)

    def get_meta(self, db_id: int, obj_store_id: int, meta_type: ObjectStoreMetadataType):
        record = self._metas.get((db_id, obj_store_id, meta_type))
        if not record:
            return None

        if meta_type == ObjectStoreMetadataType.StoreName:
            return record.value.decode("utf-16-be")

        # TODO
        raise NotImplementedError()


class IndexedDbRecord:
    def __init__(self, owner: "IndexedDb", db_id: int, obj_store_id: int, key: IdbKey, value: typing.Any):
        self.owner = owner
        self.db_id = db_id
        self.obj_store_id = obj_store_id
        self.key = key
        self.value = value

    def resolve_blob_index(self, blob_index: ccl_blink_value_deserializer.BlobIndex) -> io.BytesIO:
        return self.owner.get_blob(self.db_id, self.obj_store_id, self.key.raw_key, blob_index.index_id)


class IndexedDb:
    def __init__(self, leveldb_dir: os.PathLike, leveldb_blob_dir: os.PathLike = None):
        self._db = ccl_leveldb.RawLevelDb(leveldb_dir)
        self._blob_dir = leveldb_blob_dir
        self.global_metadata = GlobalMetadata(self._get_raw_global_metadata())
        self.database_metadata = DatabaseMetadata(self._get_raw_database_metadata())
        self.object_store_meta = ObjectStoreMetadata(self._get_raw_object_store_metadata())

        self._blob_lookup_cache = {}

    def get_database_metadata(self, db_id: int, meta_type: DatabaseMetadataType):
        return self.database_metadata.get_meta(db_id, meta_type)

    def get_object_store_metadata(self, db_id: int, obj_store_id: int, meta_type: ObjectStoreMetadataType):
        return self.object_store_meta.get_meta(db_id, obj_store_id, meta_type)

    def _get_raw_global_metadata(self, live_only=True) -> typing.Dict[bytes, ccl_leveldb.Record]:
        # Global metadata has the prefix 0 0 0 0
        # (the just byte would usually be the keyprefix datatype - special case for global metadata)
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")
        meta = {}
        for record in self._db.iterate_records_raw(reverse=True):
            if record.key.startswith(b"\x00\x00\x00\x00") and record.state == ccl_leveldb.KeyState.Live:
                # we only want live keys and the newest version thereof (highest seq)
                if record.key not in meta or meta[record.key].seq < record.seq:
                    meta[record.key] = record

        return meta

    def _get_raw_database_metadata(self, live_only=True):
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")

        db_meta = {}

        for db_id in self.global_metadata.db_ids:
            if db_id.dbid_no > 0x7f:
                raise NotImplementedError("there could be this many dbs, but I don't support it yet")

            prefix = bytes([0, db_id.dbid_no, 0, 0])
            for record in self._db.iterate_records_raw(reverse=True):
                if record.key.startswith(prefix) and record.state == ccl_leveldb.KeyState.Live:
                    # we only want live keys and the newest version thereof (highest seq)
                    meta_type = record.key[len(prefix)]
                    db_meta[(db_id.dbid_no, meta_type)] = record

        return db_meta

    def _get_raw_object_store_metadata(self, live_only=True):
        if not live_only:
            raise NotImplementedError("Deleted metadata not implemented yet")

        os_meta = {}

        for db_id in self.global_metadata.db_ids:
            if db_id.dbid_no > 0x7f:
                raise NotImplementedError("there could be this many dbs, but I don't support it yet")

            prefix = bytes([0, db_id.dbid_no, 0, 0, 50])

            for record in self._db.iterate_records_raw(reverse=True):
                if record.key.startswith(prefix) and record.state == ccl_leveldb.KeyState.Live:
                    # we only want live keys and the newest version thereof (highest seq)
                    objstore_id, varint_raw = _le_varint_from_bytes(record.key[len(prefix):])
                    meta_type = record.key[len(prefix) + len(varint_raw)]

                    old_version = os_meta.get((db_id.dbid_no, objstore_id, meta_type))

                    if old_version is None or old_version.seq < record.seq:
                        os_meta[(db_id.dbid_no, objstore_id, meta_type)] = record

        return os_meta

    def iterate_records(
            self, db_id: int, store_id: int, *,
            live_only=True, bad_deserializer_data_handler: typing.Callable[[IdbKey, bytes], typing.Any] = None):
        if db_id > 0x7f or store_id > 0x7f:
            raise NotImplementedError("there could be this many dbs, but I don't support it yet")

        blink_deserializer = ccl_blink_value_deserializer.BlinkV8Deserializer()

        # goodness me this is a slow way of doing things
        prefix = bytes([0, db_id, store_id, 1])
        for record in self._db.iterate_records_raw():
            if record.key.startswith(prefix):
                key = IdbKey(record.key[len(prefix):])
                if not record.value:
                    # empty values will obviously fail, returning None is probably better than dying.
                    return key, None
                value_version, varint_raw = _le_varint_from_bytes(record.value)
                val_idx = len(varint_raw)
                # read the blink envelope
                blink_type_tag = record.value[val_idx]
                if blink_type_tag != 0xff:
                    # TODO: probably don't want to fail hard here long term...
                    raise ValueError("Blink type tag not present")
                val_idx += 1

                blink_version, varint_raw = _le_varint_from_bytes(record.value[val_idx:])

                val_idx += len(varint_raw)

                obj_raw = io.BytesIO(record.value[val_idx:])
                deserializer = ccl_v8_value_deserializer.Deserializer(
                    obj_raw, host_object_delegate=blink_deserializer.read)
                try:
                    value = deserializer.read()
                except Exception:
                    if bad_deserializer_data_handler is not None:
                        bad_deserializer_data_handler(key, record.value[val_idx:])
                    raise
                yield IndexedDbRecord(self, db_id, store_id, key, value)

    def get_blob_info(self, db_id: int, store_id: int, raw_key: bytes, file_index: int):
        if db_id > 0x7f or store_id > 0x7f:
            raise NotImplementedError("there could be this many dbs, but I don't support it yet")

        if result := self._blob_lookup_cache.get((db_id, store_id, raw_key, file_index)):
            return result

        # goodness me this is a slow way of doing things,
        # TODO: we should at least cache along the way to our record
        prefix = bytes([0, db_id, store_id, 3])
        for record in self._db.iterate_records_raw():
            if record.key.startswith(prefix):
                buff = io.BytesIO(record.value)
                idx = 0
                while buff.tell() < len(record.value):
                    blob_info = IndexedDBExternalObject.from_stream(buff)
                    self._blob_lookup_cache[(db_id, store_id, raw_key, idx)] = blob_info
                    idx += 1
                break

        if result := self._blob_lookup_cache.get((db_id, store_id, raw_key, file_index)):
            return result
        else:
            raise KeyError((db_id, store_id, raw_key, file_index))

    def get_blob(self, db_id: int, store_id: int, raw_key: bytes, file_index: int) -> io.BytesIO:
        # Some detail here: https://github.com/chromium/chromium/blob/master/content/browser/indexed_db/docs/README.md
        if self._blob_dir is None:
            raise ValueError("Can't resolve blob if blob dir is not set")
        info = self.get_blob_info(db_id, store_id, raw_key, file_index)

        # TODO: what is the 00 folder? When does it fill up? How does it apply to the file numbers?







