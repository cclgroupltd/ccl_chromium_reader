# ccl_chrome_indexeddb
This (in retrospect, badly named) repository contains (sometimes partial)
re-implementations of the technologies used by Chrome/Chromium/Chrome-esque
applications to store data in a range of data-stores in Python. These libraries 
provide programmatic access to these data-stores with a digital forensics slant
(e.g. for most artefacts, offsets or IDs for the data are provided so that they 
can be located and manually checked).

The technologies supported are:
* Snappy decompression
* LevelDB
* Protobuf
* Pickles
* V8 object deserialization
* Blink object deserialization
* IndexedDB
* Web Storage (Local Storage and Session Storage)
* Cache (both Block File and Simple formats)
* SNSS Session files (partial support)
* FileSystem API
* Notifications API (Platform Notifications)
* Downloads (from shared_proto_db)

Additionally, there are a number of utility scripts included such as:
* `ccl_chromium_cache.py` - using the cache library as a command line tool dumps
  the cache and all HTTP header information.
* `ccl_chrome_audit.py` - a tool which can be used to scan the data-stored supported
  by the included libraries, plus a couple more, for records related to a host -
  designed as a research tool into data stored by web apps.


## Python Versions
The code in this library was written and tested using Python 3.10. It *should* work
with 3.9, but uses language features which were not present in earlier versions.
Some parts of the library will probably work OK going back a few versions, but if
you report bugs related to any version before 3.10, the first question will be: can
you upgrade to 3.10?

## A Note On Requirements
This repository contains a `requirements.txt` in the pip format. The dependencies 
listed are only required for the `ccl_chrome_audit.py` script or when using the 
`ccl_chromium_cache` module as a script for dumping the cache; the libraries work
using only the other scripts in this repository and the Python standard library.

## Documentation
The documentation in the libraries is currently sparser than ideal, but some 
recent work has been undertaken to add more usage strings and fill in some gaps
in the type-hints. We welcome pull requests to fill in gaps in the documentation.

## ccl_chrome_audit
This script audits multiple data stores in a Chrom(e|ium) profile folder based on
a fragment (regex) of a host name. It is designed to aid in research into web apps
by quickly highlighting what data related to that domain is stored where (also of
us with Electron apps etc.)

### Caveats
At the moment, the script is designed primarily for use on Windows and on the 
host where the data was populated (this is because of the Cookie decryption being
achieved using DPAPI). 

### Usage
```
ccl_chrome_audit.py <chrome profile folder> [cache folder (for mobile)]
```

### Current Supported Data Sources
* Bookmarks
* History
* Downloads (from History)
* Downloads (from shared_proto_db)
* Favicons
* Cache
* Cookies
* Local Storage
* Session Storage
* IndexedDb
* File System API
* Platform Notifications 
* Logins
* Sessions (SNSS)


## IndexedDB
The `ccl_chromium_indexeddb.py` library processes IndexedDB data found in Chrome et al. 

### Blog
Read a blog on the subject here: https://www.cclsolutionsgroup.com/post/indexeddb-on-chromium

### Caveats
There is a fair amount of work yet to be done in terms of documentation, but 
the modules should be fine for pulling data out of IndexedDB, with the following
caveats:

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
There are two methods for accessing records - a more pythonic API using a set of 
wrapper objects and a raw API which doesn't mask the underlying workings. There is
unlikely to be much benefit to using the raw API in most cases, so the wrapper objects
are recommended unless you have a compelling reason otherwise.

### Wrapper API
```python
import sys
import ccl_chromium_indexeddb

# assuming command line arguments are paths to the .leveldb and .blob folders
leveldb_folder_path = sys.argv[1]
blob_folder_path = sys.argv[2]

# open the indexedDB:
wrapper = ccl_chromium_indexeddb.WrappedIndexDB(leveldb_folder_path, blob_folder_path)

# You can check the databases present using `wrapper.database_ids`

# Databases can be accessed from the wrapper in a number of ways:
db = wrapper[2]  # accessing database using id number
db = wrapper["MyTestDatabase"]  # accessing database using name (only valid for single origin indexedDB instances)
db = wrapper["MyTestDatabase", "file__0@1"]  # accessing the database using name and origin
# NB using name and origin is likely the preferred option in most cases

# The wrapper object also supports checking for databases using `in`

# You can check for object store names using `db.object_store_names`

# Object stores can be accessed from the database in a number of ways:
obj_store = db[1]  # accessing object store using id number
obj_store = db["store"]  # accessing object store using name

# Records can then be accessed by iterating the object store in a for-loop
for record in obj_store.iterate_records():
    print(record.user_key)
    print(record.value)

    # if this record contained a FileInfo object somewhere linking
    # to data stored in the blob dir, we could access that data like
    # so (assume the "file" key in the record value is our FileInfo):
    with record.get_blob_stream(record.value["file"]) as f:
        file_data = f.read()

# By default, any errors in decoding records will bubble an exception 
# which might be painful when iterating records in a for-loop, so either
# passing True into the errors_to_stdout argument and/or by passing in an 
# error handler function to bad_deserialization_data_handler, you can 
# perform logging rather than crashing:

for record in obj_store.iterate_records(
        errors_to_stdout=True, 
        bad_deserializer_data_handler= lambda k,v: print(f"error: {k}, {v}")):
    print(record.user_key)
    print(record.value)
```

### Raw access API
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
            print(f"key: {record.user_key}")
            print(f"key: {record.value}")

            # if this record contained a FileInfo object somewhere linking
            # to data stored in the blob dir, we could access that data like
            # so (assume the "file" key in the record value is our FileInfo):
            with record.get_blob_stream(record.value["file"]) as f:
                file_data = f.read()
```

## Local Storage
`ccl_chromium_localstorage` contains functionality to read the Local Storage data from
a Chromium/Chrome profile folder.

### Blog
Read a blog on the subject here: https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage

### Using the module

An example showing how to iterate all records, grouped by host is shown below:
```python
import sys
import pathlib
import ccl_chromium_localstorage

level_db_in_dir = pathlib.Path(sys.argv[1])

# Create the LocalStoreDb object which is used to access the data
with ccl_chromium_localstorage.LocalStoreDb(level_db_in_dir) as local_storage:
    for storage_key in local_storage.iter_storage_keys():
        print(f"Getting records for {storage_key}")
      
        for record in local_storage.iter_records_for_storage_key(storage_key):
            # we can attempt to associate this record with a batch, which may
            # provide an approximate timestamp (withing 5-60 seconds) for this
            # record.
            batch = local_storage.find_batch(record.leveldb_seq_number)
            timestamp = batch.timestamp if batch else None
            print(record.leveldb_seq_number, record.script_key, record.value, sep="\t")

```

## Session Storage
`ccl_chromium_sessionstorage` contains functionality to read the Session Storage data from
a Chromium/Chrome profile folder.

### Blog
Read a blog on the subject here: https://www.cclsolutionsgroup.com/post/chromium-session-storage-and-local-storage

### Using the module
An example showing how to iterate all records, grouped by host is shown below:

```python
import sys
import pathlib
import ccl_chromium_sessionstorage

level_db_in_dir = pathlib.Path(sys.argv[1])

# Create the SessionStoreDb object which is used to access the data
with ccl_chromium_sessionstorage.SessionStoreDb(level_db_in_dir) as session_storage: 
    for host in session_storage.iter_hosts():
        print(f"Getting records for {host}")
        for key, values in session_storage.get_all_for_host(host).items():
            for value in values:
                print(value.leveldb_sequence_number, value.guid, key, value.value, sep="\t")

```

## Cache
`ccl_chromium_cache` contains functionality for reading Chromium cache data (both 
block file and simple cache formats). It can be used to programmatically access 
cache data and metadata (including http headers).

### CLI
Executing the module as a script allows you to dump a cache (either format) and 
collate all metadata into a csv file.

```
USAGE: ccl_chromium_cache.py <cache input dir> <out dir>

```

### Using the module
The main() function (which provides the CLI) in the module shows the full 
process of detecting the cache type, reading data and metadata from the cache.




