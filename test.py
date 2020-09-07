import sys
import pathlib
import ccl_v8_value_deserializer
import  ccl_blink_value_deserializer

f = open(sys.argv[1], "rb")
deserializr = ccl_v8_value_deserializer.Deserializer(
    f, ccl_blink_value_deserializer.BlinkV8Deserializer().read)
print(deserializr.read())

