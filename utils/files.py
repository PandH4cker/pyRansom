from typing import IO


def getFileSize(reader: IO) -> int:
    reader.seek(0, 2)
    return reader.tell()
