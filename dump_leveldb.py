import sys
import csv
import ccl_leveldb
import pathlib


def main(args):
    input_path = args[0]
    output_path = "leveldb_dump.csv"
    if len(args) > 1:
        output_path = args[1]

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


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {pathlib.Path(sys.argv[0]).name} <in dir path> [outpath.csv]")
        exit(1)
    main(sys.argv[1:])
