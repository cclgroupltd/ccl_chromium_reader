# ccl_chrome_indexeddb
This repository contains (sometimes partial) re-implementations of the technologies involved in reading IndexedDB data in Chrome-esque applications.
This includes:
* Snappy decompression
* LevelDB
* V8 object deserialization
* Blink object deserialization
* IndexedDB wrapper

There is a fair amount of work yet to be done in terms of documentation and
creating a more pythonic wrapper around some of the raw functions, but the
modules should be fine for pulling data out of IndexedDB, with the following
caveats:

### Caveats
#### LevelDB deleted data
The LevelDB module will spit out live and deleted/old versions of records
indiscriminately; it's possible to differentiate between them with some
work, but that hasn't really been baked into the modules as they currently
stand. So you are getting deleted data "for free" currently...whether you
want it or not.

#### Blink data types
I am fairly satisfied that all the possible V8 object types are accounted for
(but I'm happy to be shown otherwise and get that fixed of course!), but it
is likely that the hosted Blink objects aren't all there yet; so if you hit
upon an error coming from inside ccl_blink_value_deserializer and can point
me towards test data, I'd be very thankful!

#### Cyclic references
It is noted in the V8 source that recursive referencing is possible in the
serialization, we're not yet accounting for that so if Python throws a
`RecursionError` that's likely what you're seeing. The plan is to use a 
similar approach to ccl_bplist where the collection types are subclassed and
do Just In Time resolution of the items, but that isn't done yet.

## Using the modules
As previously stated, there is "some" work to be done with the API,
but in its current form, to read from an IndexedDB LevelDB folder:

```python
import sys
import ccl_chromium_indexeddb

# assuming command line arguments are paths to the .leveldb and .blob folders
leveldb_folder_path = sys.argv[1]
blob_folder_path = sys.argv[2]

# open the database:
db = ccl_chromium_indexeddb.IndexedDb(leveldb_folder_path, blob_folder_path)

# there can be multiple databases, so we need to iterate through them (NB 
# DatabaseID objects contain additional metadata, they aren't just ints):
for db_id_meta in db.global_metadata.db_ids:
    # and within each database, there will be multiple object stores so we
    # will need to know the maximum object store number (this process will be
    # cleaned up in future releases):
    max_objstore_id = db.get_database_metadata(
            db_id_meta.dbid_no, 
            ccl_chromium_indexeddb.DatabaseMetadataType.MaximumObjectStoreId)
    
    # if the above returns None, then there are no stores in this db
    if max_objstore_id is None:
        continue

    # there may be multiple object stores, so again, we iterate through them
    # this time based on the id number. Object stores start at id 1 and the
    # max_objstore_id is inclusive:
    for obj_store_id in range(1, max_objstore_id + 1):
        # now we can ask the indexeddb wrapper for all records for this db
        # and object store:
        for record in db.iterate_records(db_id_meta.dbid_no, obj_store_id):
            print(f"key: {record.key}")
            print(f"key: {record.value}")

            # if this record contained a FileInfo object somewhere linking
            # to data stored in the blob dir, we could access that data like
            # so (assume the "file" key in the record value is our FileInfo):
            with record.get_blob_stream(record.value["file"]) as f:
                file_data = f.read()
```

