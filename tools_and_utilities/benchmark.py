import sys
import pathlib
import json
import argparse
from ccl_chromium_reader import ccl_chromium_indexeddb
import time


def main(args):
    start = time.time()
    ldb_path = pathlib.Path(args.path)
    wrapper = ccl_chromium_indexeddb.WrappedIndexDB(ldb_path)

    databases = []
    for db_info in wrapper.database_ids:
        db = wrapper[db_info.dbid_no]
        stores = []
        for obj_store_name in db.object_store_names:
            obj_store = db[obj_store_name]
            record = None
            try:
                record = next(obj_store.iterate_records())
            except StopIteration:
                record = None
            stores.append({
                "object_store_id": obj_store.object_store_id,
                "name": obj_store.name,
                "sample_record": record is not None,
            })
        databases.append({
            "db_number": db.db_number,
            "name": db.name,
            "origin": db.origin,
            "object_stores": stores,
        })
    end = time.time()
    result = {
        "databases": databases,
        "elapsed_seconds": round(end - start, 3),
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False))
    else:
        for db in databases:
            print("------Database------")
            print(f"db_number={db['db_number']}; name={db['name']}; origin={db['origin']}")
            print()
            print("\t---Object Stores---")
            for store in db["object_stores"]:
                print(f"\tobject_store_id={store['object_store_id']}; name={store['name']}")
        print("Elapsed time: {} seconds.".format(int(end-start)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Benchmark Chromium IndexedDB reader.")
    parser.add_argument("path", help="Path to LevelDB directory")
    parser.add_argument("--json", action="store_true", help="Emit result as JSON")
    args = parser.parse_args()
    main(args)
