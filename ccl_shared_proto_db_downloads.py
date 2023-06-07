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

__version__ = "0.2"
__description__ = "A module for reading downloads from the Chrome/Chromium shared_proto_db leveldb data store"
__contact__ = "Alex Caithness"

import dataclasses
import datetime
import io
import os
import pathlib
import struct
import sys
import typing
import ccl_leveldb
import ccl_protobuff as pb

CHROME_EPOCH = datetime.datetime(1601, 1, 1, 0, 0, 0)


def chrome_milli_time(milliseconds: typing.Optional[int], allow_none=True) -> typing.Optional[datetime.datetime]:
    if milliseconds is not None:
        if milliseconds == 0xffffffffffffffff:
            return CHROME_EPOCH
        else:
            return CHROME_EPOCH + datetime.timedelta(milliseconds=milliseconds)
    elif allow_none:
        return None
    raise ValueError("milliseconds cannot be None")


def read_datetime(stream) -> typing.Optional[datetime.datetime]:
    return chrome_milli_time(pb.read_le_varint(stream))


# https://source.chromium.org/chromium/chromium/src/+/main:components/download/database/proto/download_entry.proto;l=86

HttpRequestHeader_Structure = {
    1: pb.ProtoDecoder("key", pb.read_string),
    2: pb.ProtoDecoder("value", pb.read_string)
}

ReceivedSlice_Structure = {
    1: pb.ProtoDecoder("offset", pb.read_le_varint),
    2: pb.ProtoDecoder("received_bytes", pb.read_le_varint),
    3: pb.ProtoDecoder("finished", lambda x: pb.read_le_varint(x) != 0)
}

InProgressInfo_Structure = {
    1: pb.ProtoDecoder("url_chain", pb.read_string),  # string
    2: pb.ProtoDecoder("referrer_url", pb.read_string),  # string
    3: pb.ProtoDecoder("site_url", pb.read_string),  # string  // deprecated
    4: pb.ProtoDecoder("tab_url", pb.read_string),  # string
    5: pb.ProtoDecoder("tab_referrer_url", pb.read_string),  # string
    6: pb.ProtoDecoder("fetch_error_body", lambda x: pb.read_le_varint(x) != 0),  # bool
    7: pb.ProtoDecoder("request_headers", lambda x: pb.read_embedded_protobuf(x, HttpRequestHeader_Structure, True)),  # HttpRequestHeader
    8: pb.ProtoDecoder("etag", pb.read_string),  # string
    9: pb.ProtoDecoder("last_modified", pb.read_string),  # string
    10: pb.ProtoDecoder("total_bytes", pb.read_le_varint),  # int64:
    11: pb.ProtoDecoder("mime_type", pb.read_string),  # string
    12: pb.ProtoDecoder("original_mime_type", pb.read_string),  # string
    13: pb.ProtoDecoder("current_path", pb.read_blob),  # bytes  // Serialized pickles to support string16: TODO
    14: pb.ProtoDecoder("target_path", pb.read_blob),  # bytes   // Serialized pickles to support string16: TODO
    15: pb.ProtoDecoder("received_bytes", pb.read_le_varint),  # int64:
    16: pb.ProtoDecoder("start_time", read_datetime),  # int64:
    17: pb.ProtoDecoder("end_time", read_datetime),  # int64:
    18: pb.ProtoDecoder("received_slices", lambda x: pb.read_embedded_protobuf(x, ReceivedSlice_Structure, True)),  # ReceivedSlice
    19: pb.ProtoDecoder("hash", pb.read_blob),  # string
    20: pb.ProtoDecoder("transient", lambda x: pb.read_le_varint(x) != 0),  # bool
    21: pb.ProtoDecoder("state", pb.read_le_varint32),  # int32:
    22: pb.ProtoDecoder("danger_type", pb.read_le_varint32),  # int32:
    23: pb.ProtoDecoder("interrupt_reason", pb.read_le_varint32),  # int32:
    24: pb.ProtoDecoder("paused", lambda x: pb.read_le_varint(x) != 0),  # bool
    25: pb.ProtoDecoder("metered", lambda x: pb.read_le_varint(x) != 0),  # bool
    26: pb.ProtoDecoder("bytes_wasted", pb.read_le_varint),  # int64:
    27: pb.ProtoDecoder("auto_resume_count", pb.read_le_varint32),  # int32:
    # 28: pb.ProtoDecoder("download_schedule", None)  # DownloadSchedule  // // Deprecated.
    # 29: pb.ProtoDecoder("reroute_info", pb),  # enterprise_connectors.DownloadItemRerouteInfo TODO
    30: pb.ProtoDecoder("credentials_mode", pb.read_le_varint32),  # int32:  // network::mojom::CredentialsMode
    31: pb.ProtoDecoder("range_request_from", pb.read_le_varint),  # int64:
    32: pb.ProtoDecoder("range_request_to", pb.read_le_varint),  # int64:
    33: pb.ProtoDecoder("serialized_embedder_download_data", pb.read_string)  # string
}

DownloadInfo_structure = {
    1: pb.ProtoDecoder("guid", pb.read_string),
    2: pb.ProtoDecoder("id", pb.read_le_varint32),
    # 3 UkmInfo
    4: pb.ProtoDecoder("in_progress_info", lambda x: pb.read_embedded_protobuf(x, InProgressInfo_Structure, True))
}

DownloadDbEntry_structure = {
    1: pb.ProtoDecoder("download_info", lambda x: pb.read_embedded_protobuf(x, DownloadInfo_structure, True))
}


@dataclasses.dataclass(frozen=True)
class Download:  # TODO: all of the parameters
    level_db_seq_no: int
    guid: str
    hash: str
    url_chain: tuple[str, ...]
    tab_url: str
    tab_referrer_url: str
    target_path: str
    mime_type: str
    original_mime_type: str
    total_bytes: str
    start_time: datetime.datetime
    end_time: datetime.datetime

    @classmethod
    def from_pb(cls, seq: int, proto: pb.ProtoObject, *, target_path_is_utf_16=True):
        if not proto.only("download_info").value:
            raise ValueError("download_info is empty")
        target_path_raw = proto.only("download_info").only("in_progress_info").only("target_path").value
        path_proto_length, path_char_count = struct.unpack("<II", target_path_raw[0:8])
        if path_proto_length != len(target_path_raw) - 4:
            raise ValueError("Invalid pickle for target path")
        if target_path_is_utf_16:
            target_path = target_path_raw[8: 8 + (path_char_count * 2)].decode("utf-16-le")
        else:
            target_path = target_path_raw[8: 8 + path_char_count].decode("utf-8")

        return cls(
            seq,
            proto.only("download_info").only("guid").value,
            proto.only("download_info").only("in_progress_info").only("hash").value.hex(),
            tuple(x.value for x in proto.only("download_info").only("in_progress_info")["url_chain"]),
            proto.only("download_info").only("in_progress_info").only("tab_url").value,
            proto.only("download_info").only("in_progress_info").only("tab_url_referrer").value,
            target_path,
            proto.only("download_info").only("in_progress_info").only("mime_type").value,
            proto.only("download_info").only("in_progress_info").only("original_mime_type").value,
            proto.only("download_info").only("in_progress_info").only("total_bytes").value,
            proto.only("download_info").only("in_progress_info").only("start_time").value,
            proto.only("download_info").only("in_progress_info").only("end_time").value
        )


def read_downloads(
        shared_proto_db_folder: typing.Union[str, os.PathLike],
        *, handle_errors=False, utf16_paths=True) -> typing.Iterator[Download]:
    ldb_path = pathlib.Path(shared_proto_db_folder)
    ldb = ccl_leveldb.RawLevelDb(ldb_path)

    for rec in ldb.iterate_records_raw():
        if rec.state != ccl_leveldb.KeyState.Live:
            continue

        key = rec.user_key
        record_type, specific_key = key.split(b"_", 1)
        if record_type == b"21":
            with io.BytesIO(rec.value) as f:
                obj = pb.ProtoObject(
                    0xa, "root", pb.read_protobuff(f, DownloadDbEntry_structure, use_friendly_tag=True))
            try:
                download = Download.from_pb(rec.seq, obj, target_path_is_utf_16=utf16_paths)
            except ValueError as ex:
                print(f"Error reading a download: {ex}", file=sys.stderr)
                if handle_errors:
                    continue
                else:
                    raise

            yield download


def report_downloads(
        shared_proto_db_folder: typing.Union[str, os.PathLike],
        out_csv_path: typing.Union[str, os.PathLike], utf16_paths=True):

    with pathlib.Path(out_csv_path).open("tx", encoding="utf-8", newline="") as out:
        writer = csv.writer(out, csv.excel, quoting=csv.QUOTE_ALL, quotechar="\"", escapechar="\\")
        writer.writerow([
            "seq no",
            "guid",
            "start time",
            "end time",
            "tab url",
            "tab referrer url",
            "download url chain",
            "target path",
            "hash",
            "total bytes",
            "mime type",
            "original mime type"
        ])
        for download in read_downloads(shared_proto_db_folder, handle_errors=True, utf16_paths=utf16_paths):
            writer.writerow([
                str(download.level_db_seq_no),
                str(download.guid),
                download.start_time,
                download.end_time,
                download.tab_url,
                download.tab_referrer_url,
                " -> ".join(download.url_chain),
                download.target_path,
                download.hash,
                download.total_bytes,
                download.mime_type,
                download.original_mime_type
            ])


if __name__ == '__main__':
    import csv
    if len(sys.argv) < 3:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <shared_proto_db folder> <out.csv> [-u8]")
        print()
        print("-u8\tutf-8 target paths (use this if target paths appear garbled in the output)")
        print()
        exit(1)
    report_downloads(sys.argv[1], sys.argv[2], "-u8" not in sys.argv[3:])
