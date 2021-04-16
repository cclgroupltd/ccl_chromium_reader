import ccl_leveldb
import csv
import sys

input_path = sys.argv[1]
output_path = "leveldb_dump.csv"
if len(sys.argv) > 2:
    output_path = sys.argv[2]

leveldb_records = ccl_leveldb.RawLevelDb(input_path)

with open(output_path, "w", newline="") as file1:
    writes = csv.writer(file1, quoting=csv.QUOTE_ALL)
    writes.writerow(
        ["key", "value", "origin_file", "file_type", "offset", "seq", "state", "was_compressed"])
    for record in leveldb_records.iterate_records_raw():
        writes.writerow([
            record.key,
            record.value,
            str(record.origin_file),
            record.file_type.name,
            record.offset,
            record.seq,
            record.state.name,
            record.was_compressed
        ])
