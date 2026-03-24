using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;

namespace PakTool;

public class PakEntry
{
    public string Name { get; set; } = string.Empty;
    public uint Offset { get; set; }
    public int Size { get; set; }
}

public enum PakFormat
{
    SpellForce1,
    SpellForce2
}

public class PakArchive
{
    public static async Task<(PakFormat Format, List<PakEntry> Entries)> ReadEntriesAsync(string pakPath)
    {
        return await Task.Run(() =>
        {
            using var fs = File.OpenRead(pakPath);
            using var br = new BinaryReader(fs, Encoding.Latin1);

            if (fs.Length >= 28)
            {
                uint firstInt = br.ReadUInt32();
                if (firstInt == 4)
                {
                    byte[] magicBytes = br.ReadBytes(24);
                    string massiveMagic = Encoding.ASCII.GetString(magicBytes);
                    if (massiveMagic.StartsWith("MASSIVE PAKFILE"))
                    {
                        return (PakFormat.SpellForce1, ReadSF1Entries(fs, br));
                    }
                }
                fs.Position = 0;
            }

            string magic = new(br.ReadChars(3));
            if (magic != "PAK")
            {
                throw new InvalidDataException("File was not a valid pak file");
            }

            byte version = br.ReadByte();
            if (version != 1)
            {
                throw new InvalidDataException("Unknown file version");
            }

            uint dirOffset = br.ReadUInt32();
            int uncompressedDirSize = br.ReadInt32();
            int compressedDirSize = br.ReadInt32();

            fs.Position = dirOffset;

            byte[] uncompressedData = new byte[uncompressedDirSize];

            // DeflateStream in .NET expects raw deflate data if we use DeflateStream, 
            // but SharpZipLib's DeflaterOutputStream uses ZLib headers by default.
            // So we use ZLibStream instead of DeflateStream.
            using (var zlib = new ZLibStream(fs, CompressionMode.Decompress, leaveOpen: true))
            {
                int totalRead = 0;
                while (totalRead < uncompressedDirSize)
                {
                    int read = zlib.Read(uncompressedData, totalRead, uncompressedDirSize - totalRead);
                    if (read == 0)
                    {
                        break;
                    }

                    totalRead += read;
                }
            }

            using var ms = new MemoryStream(uncompressedData);
            using var dirReader = new BinaryReader(ms, Encoding.Latin1);

            int fileCount = dirReader.ReadInt32();
            var entries = new List<PakEntry>(fileCount);

            for (int i = 0; i < fileCount; i++)
            {
                int nameLen = dirReader.ReadInt32();
                string name = new(dirReader.ReadChars(nameLen));
                uint offset = dirReader.ReadUInt32();
                uint nextOffset = dirReader.ReadUInt32();

                entries.Add(new PakEntry
                {
                    Name = name,
                    Offset = offset,
                    Size = (int)(nextOffset - offset)
                });
            }

            return (PakFormat.SpellForce2, entries);
        });
    }

    public static async Task UnpackAsync(string pakPath, string outDir, Action<string> onProgress)
    {
        var (format, entries) = await ReadEntriesAsync(pakPath);
        await Task.Run(() =>
        {
            using var fs = File.OpenRead(pakPath);
            Directory.CreateDirectory(outDir);

            for (int i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                onProgress?.Invoke($"Extracting ({i + 1}/{entries.Count}): {entry.Name}");

                string outPath = Path.Combine(outDir, entry.Name.Replace('\\', Path.DirectorySeparatorChar));
                Directory.CreateDirectory(Path.GetDirectoryName(outPath)!);

                fs.Position = entry.Offset;
                using var outStream = File.Create(outPath);

                byte[] buffer = new byte[8192];
                int remaining = entry.Size;
                while (remaining > 0)
                {
                    int read = fs.Read(buffer, 0, Math.Min(buffer.Length, remaining));
                    if (read == 0)
                    {
                        break;
                    }

                    outStream.Write(buffer, 0, read);
                    remaining -= read;
                }
            }
            onProgress?.Invoke("Unpack complete!");
        });
    }

    public static async Task PackAsync(string sourceDir, string outPakPath, CompressionLevel compLevel, PakFormat format, Action<string> onProgress)
    {
        if (format == PakFormat.SpellForce1)
        {
            await PackSF1Async(sourceDir, outPakPath, onProgress);
            return;
        }

        await Task.Run(() =>
        {
            var files = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            using var fs = File.Create(outPakPath);
            using var bw = new BinaryWriter(fs, Encoding.Latin1);

            // Header placeholder
            bw.Write(new char[] { 'P', 'A', 'K' });
            bw.Write((byte)1);
            bw.Write((uint)0); // dirOffset
            bw.Write(0);  // uncompressedDirSize
            bw.Write(0);  // compressedDirSize

            var entries = new List<PakEntry>();

            for (int i = 0; i < files.Length; i++)
            {
                string file = files[i];
                string relativePath = Path.GetRelativePath(sourceDir, file).Replace(Path.DirectorySeparatorChar, '\\').ToLower();

                onProgress?.Invoke($"Packing ({i + 1}/{files.Length}): {relativePath}");

                uint offset = (uint)fs.Position;
                using (var inStream = File.OpenRead(file))
                {
                    inStream.CopyTo(fs);
                }

                entries.Add(new PakEntry
                {
                    Name = relativePath,
                    Offset = offset,
                    Size = (int)(fs.Position - offset)
                });
            }

            uint dirOffset = (uint)fs.Position;

            // Build directory uncompressed data
            using var dirMs = new MemoryStream();
            using var dirBw = new BinaryWriter(dirMs, Encoding.Latin1);

            dirBw.Write(entries.Count);
            foreach (var entry in entries)
            {
                dirBw.Write(entry.Name.Length);
                dirBw.Write(entry.Name.ToCharArray());
                dirBw.Write(entry.Offset);
                dirBw.Write(entry.Offset + (uint)entry.Size);
            }

            byte[] uncompressedDirData = dirMs.ToArray();
            int uncompressedDirSize = uncompressedDirData.Length;

            // Compress directory
            using var compMs = new MemoryStream();
            using (var zlib = new ZLibStream(compMs, compLevel, leaveOpen: true))
            {
                zlib.Write(uncompressedDirData, 0, uncompressedDirData.Length);
            }

            byte[] compDirData = compMs.ToArray();
            int compressedDirSize = compDirData.Length;

            fs.Write(compDirData, 0, compDirData.Length);

            // Update header
            fs.Position = 4;
            bw.Write(dirOffset);
            bw.Write(uncompressedDirSize);
            bw.Write(compressedDirSize);

            onProgress?.Invoke("Pack complete!");
        });
    }

    private static async Task PackSF1Async(string sourceDir, string outPakPath, Action<string> onProgress)
    {
        await Task.Run(() =>
        {
            var files = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            using var fs = File.Create(outPakPath);
            using var bw = new BinaryWriter(fs, Encoding.Latin1);

            // Reserve space for header (92 bytes)
            byte[] header = new byte[92];
            bw.Write(header);

            var entries = new List<SF1FileEntry>();
            var nameListMs = new MemoryStream();
            var nameListBw = new BinaryWriter(nameListMs, Encoding.Latin1);

            // Write 2 dummy bytes at the start of name list
            nameListBw.Write((byte)0);
            nameListBw.Write((byte)0);

            var dirOffsets = new Dictionary<string, uint>();

            uint WriteReversedString(string s)
            {
                uint offset = (uint)nameListMs.Position;
                var bytes = Encoding.Latin1.GetBytes(s);
                Array.Reverse(bytes);
                nameListBw.Write(bytes);
                nameListBw.Write((byte)0);
                return offset;
            }

            for (int i = 0; i < files.Length; i++)
            {
                string file = files[i];
                string relativePath = Path.GetRelativePath(sourceDir, file).Replace(Path.DirectorySeparatorChar, '\\').ToLower();
                string dirName = Path.GetDirectoryName(relativePath) ?? "";
                string fileName = Path.GetFileName(relativePath);

                onProgress?.Invoke($"Packing SF1 ({i + 1}/{files.Length}): {relativePath}");

                uint dirOffset = 0;
                if (!string.IsNullOrEmpty(dirName))
                {
                    if (!dirOffsets.TryGetValue(dirName, out dirOffset))
                    {
                        dirOffset = WriteReversedString(dirName);
                        dirOffsets[dirName] = dirOffset;
                    }
                }

                uint nameOffset = WriteReversedString(fileName) - 2;

                entries.Add(new SF1FileEntry
                {
                    Size = 0, // Will update later
                    Offset = 0, // Will update later
                    NameOffset = nameOffset,
                    DirOffset = dirOffset,
                    FullPath = file
                });
            }

            // Write FAT
            foreach (var entry in entries)
            {
                bw.Write(entry.Size);
                bw.Write(entry.Offset);
                bw.Write(entry.NameOffset);
                bw.Write(entry.DirOffset);
            }

            // Write NameList
            byte[] nameListData = nameListMs.ToArray();
            bw.Write(nameListData);

            uint dataStartOffset = (uint)fs.Position;

            // Write file data and update FAT entries
            for (int i = 0; i < entries.Count; i++)
            {
                var entry = entries[i];
                uint fileOffset = (uint)fs.Position - dataStartOffset;

                using (var inStream = File.OpenRead(entry.FullPath))
                {
                    inStream.CopyTo(fs);
                }

                entry.Offset = fileOffset;
                entry.Size = (uint)(fs.Position - dataStartOffset - fileOffset);
                entries[i] = entry;
            }

            uint archiveSize = (uint)fs.Position;

            // Go back and update FAT with correct sizes and offsets
            fs.Position = 92;
            foreach (var entry in entries)
            {
                bw.Write(entry.Size);
                bw.Write(entry.Offset);
                bw.Write(entry.NameOffset);
                bw.Write(entry.DirOffset);
            }

            // Update Header
            fs.Position = 0;
            bw.Write((uint)4); // VersionNum

            byte[] idBytes = new byte[24];
            var magicStr = "MASSIVE PAKFILE V 4.0\r\n";
            Encoding.ASCII.GetBytes(magicStr).CopyTo(idBytes, 0);
            bw.Write(idBytes);

            byte[] unknown = new byte[44];
            bw.Write(unknown);

            bw.Write((uint)0); // Unknown2
            bw.Write((uint)entries.Count); // numFiles
            bw.Write((uint)0); // rootIndex
            bw.Write(dataStartOffset);
            bw.Write(archiveSize);

            onProgress?.Invoke("Pack complete!");
        });
    }

    private static List<PakEntry> ReadSF1Entries(FileStream fs, BinaryReader br)
    {
        var entries = new List<PakEntry>();

        fs.Position = 76;
        uint numFiles = br.ReadUInt32();
        uint rootIndex = br.ReadUInt32();
        uint dataStartOffset = br.ReadUInt32();
        uint archiveSize = br.ReadUInt32();

        fs.Position = 92;

        var fileEntries = new SF1FileEntry[numFiles];
        for (int i = 0; i < numFiles; i++)
        {
            fileEntries[i] = new SF1FileEntry
            {
                Size = br.ReadUInt32(),
                Offset = br.ReadUInt32(),
                NameOffset = br.ReadUInt32() & 0x00FFFFFF,
                DirOffset = br.ReadUInt32() & 0x00FFFFFF
            };
        }

        long nameListStart = fs.Position;

        string ReadReversedString(uint offset)
        {
            if (nameListStart + offset >= fs.Length)
            {
                return "unknown";
            }

            fs.Position = nameListStart + offset;
            var bytes = new List<byte>();
            while (fs.Position < fs.Length)
            {
                byte b = br.ReadByte();
                if (b == 0)
                {
                    break;
                }

                bytes.Add(b);
            }
            bytes.Reverse();
            // Use Latin1 to safely decode single-byte characters used in older games
            return Encoding.Latin1.GetString(bytes.ToArray());
        }

        foreach (var entry in fileEntries)
        {
            string fileName = ReadReversedString(entry.NameOffset + 2);
            string dirName = "";
            if (entry.DirOffset != 0x00FFFFFF && entry.DirOffset != 0xFFFFFF)
            {
                dirName = ReadReversedString(entry.DirOffset);
            }

            string fullPath = string.IsNullOrEmpty(dirName) ? fileName : dirName + "\\" + fileName;
            fullPath = fullPath.Replace('/', '\\');

            entries.Add(new PakEntry
            {
                Name = fullPath,
                Offset = dataStartOffset + entry.Offset,
                Size = (int)entry.Size
            });
        }

        return entries;
    }

    private struct SF1FileEntry
    {
        public uint Size;
        public uint Offset;
        public uint NameOffset;
        public uint DirOffset;
        public string FullPath;
    }
}
