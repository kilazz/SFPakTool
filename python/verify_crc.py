import struct
import os

# Generate standard CRC32 table (IEEE 802.3 polynomial: 0xEDB88320)
CRC32_TABLE = []
for i in range(256):
    crc = i
    for _ in range(8):
        if crc & 1:
            crc = (crc >> 1) ^ 0xEDB88320
        else:
            crc >>= 1
    CRC32_TABLE.append(crc)


def calculate_sf1_crc(data, prev_crc=0xFFFFFFFF):
    """Calculate custom CRC32 checksum without final bitwise inversion."""
    crc = prev_crc
    for b in data:
        crc = (crc >> 8) ^ CRC32_TABLE[(crc ^ b) & 0xFF]
    return crc


def verify_file(filepath):
    if not os.path.exists(filepath):
        print(
            f"[!] File {filepath} not found! Place it in the same directory as this script."
        )
        return

    with open(filepath, "rb") as f:
        # Read 92 bytes of the header
        header = bytearray(f.read(92))

        # Extract the original hash from offset 72
        original_crc = struct.unpack_from("<I", header, 72)[0]
        print(f"[*] Original Hash in file: {hex(original_crc)}")

        # Read metadata parameters
        num_files = struct.unpack_from("<I", header, 76)[0]
        root_idx = struct.unpack_from("<I", header, 80)[0]
        data_start = struct.unpack_from("<I", header, 84)[0]
        archive_size = struct.unpack_from("<I", header, 88)[0]

        print(f"[*] File count: {num_files}")
        print(f"[*] Root Index: {root_idx}")
        print(f"[*] data_start: {data_start}")
        print(f"[*] archive_size: {archive_size}")

        # Replace the checksum field with 0xFFFFFFFF for calculations
        struct.pack_into("<I", header, 72, 0xFFFFFFFF)

        # Read the file metadata table
        file_table_size = num_files * 16
        file_table_bytes = f.read(file_table_size)

        # Read the string table
        string_table_size = data_start - file_table_size - 92
        string_table_bytes = f.read(string_table_size)

        # Calculate the checksum using our algorithm
        seed = calculate_sf1_crc(header)
        file_table_crc = calculate_sf1_crc(file_table_bytes, seed)
        final_crc = calculate_sf1_crc(string_table_bytes, file_table_crc)

        print(f"[*] Calculated Hash: {hex(final_crc)}")

        if final_crc == original_crc:
            print("[+] SUCCESS! The calculated CRC32 matches the original checksum!")
        else:
            print("[-] ERROR! Hash mismatch. The algorithm formula needs adjustment.")


# Replace the file name if your original file is named differently
verify_file("sf0.pak")
