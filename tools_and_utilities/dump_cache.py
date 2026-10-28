import sys
import pathlib
import ccl_chromium_reader.ccl_chromium_cache as cache


if len(sys.argv) < 3:
    print(f"USAGE: {pathlib.Path(sys.argv[0]).name} <cache input dir> <out dir>")
    exit(1)
cache.main(sys.argv[1:])

