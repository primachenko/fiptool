import struct
import uuid
import os
import logging
from typing import Union, IO, Optional
from io import BytesIO

# Константы для структуры FIP
FIP_HEADER_MAGIC = 0xAA640001
FIP_HEADER_SIZE = 16
FIP_ENTRY_DESC_SIZE = 40

# Форматы для unpack
FIP_HEADER_FORMAT = '<IIQ'  # magic, reserved, flags (4 + 4 + 8 = 16 байт)
FIP_ENTRY_FORMAT = '<16sQQQ'  # uuid, offset, size, flags (16 + 8 + 8 + 8 = 40 байт)


def parse_fip_header(fip_file: IO[bytes]) -> tuple[int, int, int]:
    """ Парсинг заголовка FIP """
    fip_file.seek(0)
    header_data = fip_file.read(FIP_HEADER_SIZE)

    if len(header_data) < struct.calcsize(FIP_HEADER_FORMAT):
        raise ValueError("Недостаточно данных для заголовка FIP.")

    magic, reserved, flags = struct.unpack(
        FIP_HEADER_FORMAT, header_data[:struct.calcsize(FIP_HEADER_FORMAT)]
    )

    logging.info(f"Magic: {hex(magic)}")
    logging.info(f"Reserved: {reserved}")
    logging.info(f"Flags: {flags}")

    if magic != FIP_HEADER_MAGIC:
        raise ValueError(f"Неверное магическое число FIP: {hex(magic)}")

    return magic, reserved, flags


def parse_fip_entries(fip_file: IO[bytes]) -> list[dict[str, Union[uuid.UUID, int]]]:
    """ Парсинг записей в FIP """
    fip_file.seek(FIP_HEADER_SIZE)
    entries = []

    toc_terminator = bytes(16)
    while True:
        entry_data = fip_file.read(FIP_ENTRY_DESC_SIZE)
        if len(entry_data) < FIP_ENTRY_DESC_SIZE:
            break

        uuid_bytes, offset, size, flags = struct.unpack(
            FIP_ENTRY_FORMAT, entry_data
        )

        if uuid_bytes == toc_terminator:
            break

        entry_uuid = uuid.UUID(bytes=uuid_bytes)

        entries.append({
            'uuid': entry_uuid,
            'offset': offset,
            'size': size,
            'flags': flags
        })

    return entries


def list_fip_contents(fip_image: Union[str, IO[bytes]]) -> None:
    """ Список содержимого FIP """
    fip_file = _open_fip_file(fip_image)
    parse_fip_header(fip_file)
    entries = parse_fip_entries(fip_file)

    print("FIP Table of Contents:")
    for entry in entries:
        print(
            f"UUID: {entry['uuid']} - Offset: {entry['offset']} - "
            f"Size: {entry['size']} - Flags: {entry['flags']}"
        )


def extract_entry(
    fip_image: Union[str, IO[bytes]],
    entry_uuid: uuid.UUID,
    output: Union[str, IO[bytes]]
) -> None:
    """ Извлечение entry по UUID """
    fip_file = _open_fip_file(fip_image)
    entries = parse_fip_entries(fip_file)

    for entry in entries:
        if entry['uuid'] == entry_uuid:
            fip_file.seek(entry['offset'])
            data = fip_file.read(entry['size'])

            if isinstance(output, str):
                with open(output, 'wb') as output_file:
                    output_file.write(data)
                log_destination = output
            else:
                output.write(data)
                log_destination = f"<BytesIO object at {hex(id(output))}>"

            logging.info(f"Extracted entry {entry_uuid} of size {len(data)} bytes to {log_destination}")
            return

    logging.error(f"Entry with UUID {entry_uuid} not found.")


def add_entry(
    fip_image: Union[str, IO[bytes]],
    entry_uuid: Optional[uuid.UUID],
    entry_file: IO[bytes]
) -> uuid.UUID:
    """ Добавление нового entry в FIP """
    if entry_uuid is None:
        entry_uuid = uuid.uuid4()

    fip_file = _open_fip_file(fip_image, mode='r+b')
    entries = parse_fip_entries(fip_file)
    for entry in entries:
        if entry['uuid'] == entry_uuid:
            raise ValueError(f"Entry with UUID {entry_uuid} already exists.")

    fip_file.seek(0, os.SEEK_END)
    new_entry_offset = fip_file.tell()

    data = entry_file.read()
    entry_size = len(data)

    toc_end_offset = FIP_HEADER_SIZE + len(entries) * FIP_ENTRY_DESC_SIZE
    fip_file.seek(toc_end_offset)
    toc_terminator_entry = fip_file.read(FIP_ENTRY_DESC_SIZE)
    remaining_data = fip_file.read()

    if toc_terminator_entry[:16] != bytes(16):
        raise ValueError("Invalid ToC Terminator")

    new_entry = {
        'uuid': entry_uuid,
        'offset': new_entry_offset,
        'size': entry_size,
        'flags': 0
    }
    entries.append(new_entry)

    additional_toc_size = FIP_ENTRY_DESC_SIZE
    for entry in entries:
        entry['offset'] += additional_toc_size

    fip_file.seek(FIP_HEADER_SIZE)
    for entry in entries:
        entry_data = struct.pack(
            FIP_ENTRY_FORMAT,
            entry['uuid'].bytes,
            entry['offset'],
            entry['size'],
            entry['flags']
        )
        fip_file.write(entry_data)

    fip_file.write(toc_terminator_entry)
    if remaining_data:
        fip_file.write(remaining_data)

    fip_file.seek(0, os.SEEK_END)
    fip_file.write(data)

    logging.info(f"Added entry {entry_uuid} of size {entry_size} bytes")
    return entry_uuid


def delete_entry(fip_image: Union[str, IO[bytes]], entry_uuid: uuid.UUID) -> None:
    """ Удаление entry по UUID """
    fip_file = _open_fip_file(fip_image, mode='r+b')
    entries = parse_fip_entries(fip_file)
    updated_entries = [entry for entry in entries if entry['uuid'] != entry_uuid]

    if len(updated_entries) == len(entries):
        raise ValueError(f"Entry with UUID {entry_uuid} not found.")

    temp_fip_file = _create_temp_fip_file()

    fip_file.seek(0)
    temp_fip_file.write(fip_file.read(FIP_HEADER_SIZE))

    current_offset = FIP_HEADER_SIZE
    for i, entry in enumerate(updated_entries):
        entry_offset = FIP_HEADER_SIZE + i * FIP_ENTRY_DESC_SIZE
        entry['offset'] -= FIP_ENTRY_DESC_SIZE
        temp_fip_file.seek(entry_offset)
        temp_fip_file.write(struct.pack(
            FIP_ENTRY_FORMAT,
            entry['uuid'].bytes,
            entry['offset'],
            entry['size'],
            entry['flags']
        ))
        fip_file.seek(entry['offset'] + FIP_ENTRY_DESC_SIZE)
        data = fip_file.read(entry['size'])
        temp_fip_file.seek(entry['offset'])
        temp_fip_file.write(data)
        current_offset = entry['offset'] + entry['size']

    toc_terminator = bytes(40)
    temp_fip_file.seek(FIP_HEADER_SIZE + len(updated_entries) * FIP_ENTRY_DESC_SIZE)
    temp_fip_file.write(toc_terminator)

    temp_fip_file.seek(0)
    fip_file.seek(0)
    fip_file.truncate()
    fip_file.write(temp_fip_file.read())

    temp_fip_file.close()

    logging.info(f"Deleted entry {entry_uuid}")


def _open_fip_file(file: Union[str, IO[bytes]], mode: str = 'rb') -> IO[bytes]:
    """ Открытие FIP файла """
    if isinstance(file, str):
        return open(file, mode)
    return file


def _create_temp_fip_file() -> IO[bytes]:
    """ Создание временного файла FIP """
    return BytesIO()

def main() -> None:
    import sys

    if len(sys.argv) < 3:
        print("Usage: python fiptool.py <command> <fip_image> [options]")
        sys.exit(1)

    command = sys.argv[1]
    fip_image_path = sys.argv[2]

    if command == "list":
        list_fip_contents(fip_image_path)
    elif command == "extract":
        if len(sys.argv) < 5:
            print("Usage: python fiptool.py extract <fip_image> <uuid> <output_file>")
            sys.exit(1)
        entry_uuid = uuid.UUID(sys.argv[3])
        output_path = sys.argv[4]
        extract_entry(fip_image_path, entry_uuid, output_path)
    elif command == "add":
        if len(sys.argv) < 4:
            print("Usage: python fiptool.py add <fip_image> <entry_file> [uuid]")
            sys.exit(1)
        entry_path = sys.argv[3]
        entry_uuid = uuid.UUID(sys.argv[4]) if len(sys.argv) > 4 else None
        with open(entry_path, 'rb') as entry_file:
            generated_uuid = add_entry(fip_image_path, entry_uuid, entry_file)
            if entry_uuid is None:
                print(f"Generated UUID: {generated_uuid}")
    elif command == "delete":
        if len(sys.argv) < 4:
            print("Usage: python fiptool.py delete <fip_image> <uuid>")
            sys.exit(1)
        entry_uuid = uuid.UUID(sys.argv[3])
        delete_entry(fip_image_path, entry_uuid)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)

# Если запускается напрямую, выполняем тесты.
if __name__ == "__main__":
    main()
