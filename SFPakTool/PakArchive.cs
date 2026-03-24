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

public class PakArchive
{
    public static async Task<List<PakEntry>> ReadEntriesAsync(string pakPath)
    {
        return await Task.Run(() =>
        {
            using var fs = File.OpenRead(pakPath);
            using var br = new BinaryReader(fs, Encoding.Default);

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
            using var dirReader = new BinaryReader(ms, Encoding.Default);

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

            return entries;
        });
    }

    public static async Task UnpackAsync(string pakPath, string outDir, Action<string> onProgress)
    {
        var entries = await ReadEntriesAsync(pakPath);
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

    public static async Task PackAsync(string sourceDir, string outPakPath, Action<string> onProgress)
    {
        await Task.Run(() =>
        {
            var files = Directory.GetFiles(sourceDir, "*", SearchOption.AllDirectories);
            using var fs = File.Create(outPakPath);
            using var bw = new BinaryWriter(fs, Encoding.Default);

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
            using var dirBw = new BinaryWriter(dirMs, Encoding.Default);

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
            using (var zlib = new ZLibStream(compMs, CompressionLevel.Optimal, leaveOpen: true))
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
}
