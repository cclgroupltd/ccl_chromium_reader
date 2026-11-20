import argparse
import sys
import json
import pathlib
import itertools

from ccl_chromium_reader.ccl_chromium_extensions import ExtensionsReader


def main(input_path, show_only_counts, ext_ids=None):
    reader = ExtensionsReader(input_path)

    for extension in reader.extensions:
        if ext_ids and extension.id not in ext_ids:
            continue
        print()
        print("=" * 72)
        if extension.is_live:
            print(f"{extension.name} ({extension.id})")
            print(f"Description:\t{extension.description or ""}")
            print(f"Permissions:\t{extension.permissions}")
            print(f"Version:\t{extension.version}")
            print(f"Author:\t{extension.author or ""}")
            print(f"First installed\t{extension.first_installed or ""}")
            print(f"Last Updated:\t{extension.last_updated or ""}")
            print(f"Path:\t{extension.path}")
        else:
            print(f"[Recovered Extension] {extension.id}")

        print()

        if show_only_counts:
            print(f"Extension State (unique values):"
                  f"\t{len(set((x.key, json.dumps(x.value)) for x in extension.get_state_records()))}")
            print(f"Local Settings (unique values):"
                  f"\t{len(set((x.key, json.dumps(x.value)) for x in extension.get_settings_records()))}")
            print(f"Local Storage:\t{sum(1 for _ in extension.get_localstorage())}")
            print(f"Session Storage:\t{sum(1 for _ in extension.get_sessionstorage())}")
            print(f"IndexedDB (database count):"
                  f"\t{idb.database_count if (idb := extension.get_indexeddb()) else 0}")
            print(f"File System API:\t{sum(sum(1 for _ in o.get_file_listing()) for o in extension.get_filesystem())}")
        else:
            print("Extension State:")
            rec = loop_sentinel = object()
            for rec in extension.get_state_records():
                print(f"\tKey:\t{rec.key}")
                print(f"\tValue:\t{json.dumps(rec.value)}")
            if rec is loop_sentinel:
                print("(no records)")
            print()

            print("Local Settings:")
            rec = loop_sentinel = object()
            for rec in extension.get_settings_records():
                print(f"\tKey:\t{rec.key}")
                print(f"\tValue:\t{json.dumps(rec.value)}")
            if rec is loop_sentinel:
                print("(no records)")
            print()

            print("Local Storage:")
            rec = loop_sentinel = object()
            for rec in extension.get_localstorage():
                print(f"\tKey:\t{rec.script_key}")
                print(f"\tValue:\t{rec.value}")
            if rec is loop_sentinel:
                print("(no records)")
            print()

            print("Session Storage:")
            rec = loop_sentinel = object()
            for rec in extension.get_sessionstorage():
                print(f"\tKey:\t{rec.key}")
                print(f"\tValue:\t{rec.value}")
            if rec is loop_sentinel:
                print("(no records)")
            print()

            print("IndexedDB:")
            idb = extension.get_indexeddb()
            if idb:
                for dbid in idb.database_ids:
                    db = idb[dbid]
                    print(f"\t{db.name}")
                    for objstore_name in db.object_store_names:
                        objstore = db[objstore_name]
                        print(f"\t\t{objstore.name}")
                        for rec in objstore.iterate_records(errors_to_stdout=True):
                            print(f"\t\t\tKey:\t{rec.key}")
                            print(f"\t\t\tValue:\t{rec.value}")
            else:
                print("(no records)")

            print()

            print("File System API:")
            origin_store = loop_sentinel = object()
            for origin_store in extension.get_filesystem():
                for file_id, file_info in origin_store.get_file_listing():
                    print(f"\t\"{file_info.name}\" {file_info.data_path}")
            if origin_store is loop_sentinel:
                print("(no records)")


if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("profile_folder", help="path to the profile folder to process")
    argparser.add_argument(
        "extension_id",
        help="extension ids to process (all will be processed if not provided)", nargs="*", default=None)
    argparser.add_argument(
        "-c", "--counts_only", help="only display counts instead of records", action="store_true")
    args = argparser.parse_args()
    main(args.profile_folder, args.counts_only, args.extension_id)
