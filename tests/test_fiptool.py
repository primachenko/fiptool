import unittest
import uuid
import struct
from io import BytesIO
import fiptool.core as fiptool
import hashlib
from unittest.mock import patch, mock_open


class TestFipTool(unittest.TestCase):

    def setUp(self) -> None:
        self.fip_header = struct.pack(fiptool.FIP_HEADER_FORMAT, fiptool.FIP_HEADER_MAGIC, 0, 0)
        self.test_uuid = uuid.UUID('12345678-1234-5678-1234-567812345678')
        self.test_data = b'test_data'
        self.correct_offset = 96
        self.fip_entry = struct.pack(fiptool.FIP_ENTRY_FORMAT, self.test_uuid.bytes, self.correct_offset, len(self.test_data), 0)
        self.toc_terminator = struct.pack(fiptool.FIP_ENTRY_FORMAT, bytes(16), 0, 0, 0)
        self.fip_file_data = self.fip_header + self.fip_entry + self.toc_terminator + self.test_data
        self.fip_file = BytesIO(self.fip_file_data)
        self.original_hash = hashlib.sha256(self.fip_file_data).hexdigest()

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_parse_fip_header(self, mock_file) -> None:
        mock_file.return_value = self.fip_file
        magic, reserved, flags = fiptool.parse_fip_header(self.fip_file)
        self.assertEqual(magic, fiptool.FIP_HEADER_MAGIC)
        self.assertEqual(reserved, 0)
        self.assertEqual(flags, 0)

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_parse_fip_entries(self, mock_file) -> None:
        mock_file.return_value = self.fip_file
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]['uuid'], self.test_uuid)
        self.assertEqual(entries[0]['offset'], self.correct_offset)
        self.assertEqual(entries[0]['size'], len(self.test_data))
        self.assertEqual(entries[0]['flags'], 0)

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_extract_entry(self, mock_file) -> None:
        mock_file.return_value = self.fip_file
        output_data = BytesIO()

        with self.assertLogs(level='INFO') as log:
            fiptool.extract_entry(self.fip_file, self.test_uuid, output_data)

        output_data.seek(0)
        extracted_data = output_data.read()
        self.assertEqual(extracted_data, self.test_data)
        self.assertIn(
            f"Extracted entry {self.test_uuid} of size {len(self.test_data)} bytes",
            log.output[0]
        )

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_add_entry(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        new_uuid = uuid.UUID('87654321-4321-8765-4321-876543218765')
        new_data = b'new_entry_data'
        new_entry_file = BytesIO(new_data)

        with self.assertLogs(level='INFO') as log:
            fiptool.add_entry(self.fip_file, new_uuid, new_entry_file)

        self.fip_file.seek(0)
        entries = fiptool.parse_fip_entries(self.fip_file)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1]['uuid'], new_uuid)

        self.fip_file.seek(entries[1]['offset'])
        read_data = self.fip_file.read(len(new_data))
        self.assertEqual(read_data, new_data)
        self.assertIn(f"Added entry {new_uuid} of size {len(new_data)} bytes", log.output[0])

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_list_fip_contents(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        with self.assertLogs(level='INFO') as log:
            fiptool.list_fip_contents(self.fip_file)
            self.assertTrue(
                any(f"UUID: {self.test_uuid}" in message for message in log.output),
                f"UUID: {self.test_uuid} not found in logs"
            )

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_extract_all_entries(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        new_entries = [
            (uuid.UUID('87654321-4321-8765-4321-876543218765'), b'entry1_data'),
            (uuid.UUID('abcdefab-cdef-abcd-efab-cdefabcdefab'), b'entry2_data'),
            (uuid.UUID('12341234-1234-1234-1234-123412341234'), b'entry3_data')
        ]

        expected_hashes = {}

        for entry_uuid, entry_data in new_entries:
            entry_file = BytesIO(entry_data)
            fiptool.add_entry(self.fip_file, entry_uuid, entry_file)
            expected_hashes[entry_uuid] = hashlib.sha256(entry_data).hexdigest()

        entries = fiptool.parse_fip_entries(self.fip_file)
        for entry in entries:
            output_data = BytesIO()
            fiptool.extract_entry(self.fip_file, entry['uuid'], output_data)
            output_data.seek(0)
            extracted_data = output_data.read()
            extracted_hash = hashlib.sha256(extracted_data).hexdigest()
            self.assertEqual(
                extracted_hash,
                expected_hashes.get(entry['uuid'], hashlib.sha256(self.test_data).hexdigest())
            )

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_add_multiple_entries(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        new_entries = [
            (uuid.UUID('87654321-4321-8765-4321-876543218765'), b'entry1_data'),
            (uuid.UUID('abcdefab-cdef-abcd-efab-cdefabcdefab'), b'entry2_data'),
            (uuid.UUID('12341234-1234-1234-1234-123412341234'), b'entry3_data')
        ]

        for entry_uuid, entry_data in new_entries:
            entry_file = BytesIO(entry_data)
            with self.assertLogs(level='INFO') as log:
                fiptool.add_entry(self.fip_file, entry_uuid, entry_file)

        self.fip_file.seek(0)
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 4)  # исходная запись + 3 новые

        for i, (entry_uuid, entry_data) in enumerate(new_entries, start=1):
            self.assertEqual(entries[i]['uuid'], entry_uuid)
            self.fip_file.seek(entries[i]['offset'])
            read_data = self.fip_file.read(len(entry_data))
            self.assertEqual(read_data, entry_data)

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_delete_entry(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        with self.assertLogs(level='INFO') as log:
            fiptool.delete_entry(self.fip_file, self.test_uuid)

        self.fip_file.seek(0)
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 0)
        self.assertIn(f"Deleted entry {self.test_uuid}", log.output[0])

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_delete_entries(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        new_entries = [
            (uuid.UUID('87654321-4321-8765-4321-876543218765'), b'entry1_data'),
            (uuid.UUID('abcdefab-cdef-abcd-efab-cdefabcdefab'), b'entry2_data'),
            (uuid.UUID('12341234-1234-1234-1234-123412341234'), b'entry3_data')
        ]

        for entry_uuid, entry_data in new_entries:
            entry_file = BytesIO(entry_data)
            fiptool.add_entry(self.fip_file, entry_uuid, entry_file)

        # Проверка перед удалением
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 4)  # Исходная запись + 3 новые

        # Удаление из начала
        with self.assertLogs(level='INFO') as log:
            fiptool.delete_entry(self.fip_file, self.test_uuid)
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 3)
        self.assertNotIn(self.test_uuid, [entry['uuid'] for entry in entries])

        # Удаление из середины
        with self.assertLogs(level='INFO') as log:
            fiptool.delete_entry(self.fip_file, new_entries[1][0])
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 2)
        self.assertNotIn(new_entries[1][0], [entry['uuid'] for entry in entries])

        # Удаление из конца
        with self.assertLogs(level='INFO') as log:
            fiptool.delete_entry(self.fip_file, new_entries[2][0])
        entries = fiptool.parse_fip_entries(self.fip_file)
        self.assertEqual(len(entries), 1)
        self.assertNotIn(new_entries[2][0], [entry['uuid'] for entry in entries])

        # Проверка, что осталась только одна запись с ожидаемым UUID
        self.assertEqual(entries[0]['uuid'], new_entries[0][0])

    @patch("builtins.open", new_callable=mock_open, read_data=b"")
    def test_add_and_delete_entries_with_hash_check(self, mock_file) -> None:
        mock_file.return_value = self.fip_file

        new_entries = [
            (uuid.UUID('87654321-4321-8765-4321-876543218765'), b'entry1_data'),
            (uuid.UUID('abcdefab-cdef-abcd-efab-cdefabcdefab'), b'entry2_data'),
            (uuid.UUID('12341234-1234-1234-1234-123412341234'), b'entry3_data')
        ]

        for entry_uuid, entry_data in new_entries:
            entry_file = BytesIO(entry_data)
            fiptool.add_entry(self.fip_file, entry_uuid, entry_file)

        for entry_uuid, _ in new_entries:
            fiptool.delete_entry(self.fip_file, entry_uuid)

        for entry_uuid, entry_data in new_entries:
            entry_file = BytesIO(entry_data)
            fiptool.add_entry(self.fip_file, entry_uuid, entry_file)

        for entry_uuid, _ in reversed(new_entries):
            fiptool.delete_entry(self.fip_file, entry_uuid)

        self.fip_file.seek(0)
        final_hash = hashlib.sha256(self.fip_file.read()).hexdigest()
        self.assertEqual(final_hash, self.original_hash, "Файл после добавления и удаления записей отличается от исходного")


if __name__ == '__main__':
    unittest.main()
