import struct
import os


def compare(original_pak, source_dir):
    if not os.path.exists(original_pak):
        print(
            f"[!] File {original_pak} not found! Place it in the same directory as this script."
        )
        return

    with open(original_pak, "rb") as f:
        header = f.read(92)
        num_files = struct.unpack_from("<I", header, 76)[0]
        data_start = struct.unpack_from("<I", header, 84)[0]

        file_table_size = num_files * 16
        f.seek(92 + file_table_size)
        string_table_size = data_start - file_table_size - 92
        orig_strings_bytes = f.read(string_table_size)

    # Parse original string segments
    orig_strings = []
    offset = 0
    while offset < len(orig_strings_bytes):
        # Check files by 00 00 prefix and shift offset
        if (
            offset + 2 <= len(orig_strings_bytes)
            and orig_strings_bytes[offset : offset + 2] == b"\x00\x00"
        ):
            offset += 2

        chars = []
        while offset < len(orig_strings_bytes) and orig_strings_bytes[offset] != 0:
            chars.append(orig_strings_bytes[offset])
            offset += 1

        if chars:
            chars.reverse()
            orig_strings.append(bytes(chars).decode("latin1", errors="ignore"))
        offset += 1  # Skip null-terminator

    print(
        f"[*] Original contains {len(orig_strings)} unique text segments. Table size: {string_table_size}"
    )

    # Generate string segments using our script's logic
    files = []
    for root, _, filenames in os.walk(source_dir):
        for filename in filenames:
            files.append(os.path.join(root, filename))
    files.sort(key=lambda x: os.path.relpath(x, source_dir).replace("/", "\\"))

    our_dirs = set()
    our_files = []
    for file_path in files:
        rel_path = os.path.relpath(file_path, source_dir).replace("/", "\\")
        if rel_path.startswith(".\\"):
            rel_path = rel_path[2:]
        dir_name = os.path.dirname(rel_path)
        file_name = os.path.basename(rel_path)
        if dir_name:
            our_dirs.add(dir_name)
        our_files.append(file_name)

    our_strings = list(our_dirs) + our_files
    print(
        f"[*] Our script generates {len(our_strings)} segments without deduplication."
    )

    # Compare sets
    orig_set = set(orig_strings)
    our_set = set(our_strings)

    print("\n[!] Strings present in the ORIGINAL, but MISSING in ours:")
    diff_orig = orig_set - our_set
    if diff_orig:
        for s in sorted(diff_orig):
            print(f"  - {repr(s)}")
    else:
        print("  (empty)")

    print("\n[!] Strings present in ours, but MISSING in the ORIGINAL:")
    diff_ours = our_set - orig_set
    if diff_ours:
        for s in sorted(diff_ours):
            print(f"  - {repr(s)}")
    else:
        print("  (empty)")


# Run comparison (verify correct paths)
compare("sf0_original.pak", "F:/zzzzzzzz/extracted_pak")
