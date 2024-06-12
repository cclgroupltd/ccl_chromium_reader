"""
Copyright 2020-2024, CCL Forensics

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

import sys
import pathlib
from ccl_chromium_reader import ccl_chromium_indexeddb


def main(args):
    ldb_path = pathlib.Path(args[0])
    wrapper = ccl_chromium_indexeddb.WrappedIndexDB(ldb_path)

    for db_info in wrapper.database_ids:
        db = wrapper[db_info.dbid_no]
        print("------Database------")
        print(f"db_number={db.db_number}; name={db.name}; origin={db.origin}")
        print()
        print("\t---Object Stores---")
        for obj_store_name in db.object_store_names:
            obj_store = db[obj_store_name]
            print(f"\tobject_store_id={obj_store.object_store_id}; name={obj_store.name}")
            try:
                one_record = next(obj_store.iterate_records())
            except StopIteration:
                one_record = None
            if one_record is not None:
                print("\tExample record:")
                print(f"\tkey: {one_record.key}")
                print(f"\tvalue: {one_record.value}")
            else:
                print("\tNo records")
            print()
        print()


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <ldb dir path>")
        exit(1)
    main(sys.argv[1:])
