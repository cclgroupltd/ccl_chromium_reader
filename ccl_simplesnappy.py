import sys
import struct
import io
import typing
import enum

DEBUG = False


def log(msg):
    if DEBUG:
        print(msg)


class ElementType(enum.IntEnum):
    Literal = 0
    CopyOneByte = 1
    CopyTwoByte = 2
    CopyFourByte = 3

def _read_le_varint(stream: typing.BinaryIO):
    # this only outputs unsigned
    i = 0
    result = 0
    underlying_bytes = []
    while i < 10:  # 64 bit max possible?
        raw = stream.read(1)
        if len(raw) < 1:
            return None
        tmp, = raw
        underlying_bytes.append(tmp)
        result |= ((tmp & 0x7f) << (i * 7))
        if (tmp & 0x80) == 0:
            break
        i += 1
    return result, bytes(underlying_bytes)


def read_le_varint(stream: typing.BinaryIO):
    x = _read_le_varint(stream)
    if x is None:
        return None
    else:
        return x[0]


def read_uint16(stream: typing.BinaryIO):
    return struct.unpack("<H", stream.read(2))[0]


def read_uint24(stream: typing.BinaryIO):
    return struct.unpack("<I", stream.read(3) + b"\x00")[0]


def read_uint32(stream: typing.BinaryIO):
    return struct.unpack("<I", stream.read(4))[0]


def read_byte(stream: typing.BinaryIO):
    x = stream.read(1)
    if x:
        return x[0]

    return None


def decompress(data: typing.BinaryIO):
    uncompressed_length = read_le_varint(data)
    log(f"Uncompressed length: {uncompressed_length}")

    out = io.BytesIO()

    while True:
        start_offset = data.tell()
        log(f"Reading tag at offset {start_offset}")
        type_byte = read_byte(data)
        if type_byte is None:
            break

        log(f"Type Byte is {type_byte:02x}")

        tag = type_byte & 0x03

        log(f"Element Type is: {ElementType(tag)}")

        if tag == ElementType.Literal:
            if ((type_byte & 0xFC) >> 2) < 60:  # embedded in tag
                length = 1 + ((type_byte & 0xFC) >> 2)
                log(f"Literal length is embedded in type byte and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 60:  # 8 bit
                length = 1 + read_byte(data)
                log(f"Literal length is 8bit and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 61:  # 16 bit
                length = 1 + read_uint16(data)
                log(f"Literal length is 16bit and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 62:  # 16 bit
                length = 1 + read_uint24(data)
                log(f"Literal length is 24bit and is {length}")
            elif ((type_byte & 0xFC) >> 2) == 63:  # 16 bit
                length = 1 + read_uint32(data)
                log(f"Literal length is 32bit and is {length}")
            else:
                raise ValueError()  # cannot ever happen

            literal_data = data.read(length)
            if len(literal_data) < length:
                raise ValueError("Couldn't read enough literal data")

            out.write(literal_data)

        else:
            if tag == ElementType.CopyOneByte:
                length = ((type_byte & 0x1C) >> 2) + 4
                offset = ((type_byte & 0xE0) << 3) | read_byte(data)
            elif tag == ElementType.CopyTwoByte:
                length = 1 + ((type_byte & 0xFC) >> 2)
                offset = read_uint16(data)
            elif tag == ElementType.CopyFourByte:
                length = 1 + ((type_byte & 0xFC) >> 2)
                offset = read_uint32(data)
            else:
                raise ValueError()  # cannot ever happen

            if offset == 0:
                raise ValueError("Offset cannot be 0")

            actual_offset = out.tell() - offset
            log(f"Current Outstream Length: {out.tell()}")
            log(f"Backreference length: {length}")
            log(f"Backreference relative offset: {offset}")
            log(f"Backreference absolute offset: {actual_offset}")

            # have to read incrementally because you might have to read data that you've just written
            # this is probably a really slow way of doing this.
            for i in range(length):
                out.write(out.getbuffer()[actual_offset + i: actual_offset + i + 1].tobytes())

    result = out.getvalue()
    if uncompressed_length != len(result):
        raise ValueError("Wrong data length in uncompressed data")

    return result


if __name__ == "__main__":
    import pathlib
    import hashlib

    f = pathlib.Path(sys.argv[1]).open("rb")
    decompressed = decompress(f)
    print(decompressed)
    sha1 = hashlib.sha1()
    sha1.update(decompressed)
    print(sha1.hexdigest())
