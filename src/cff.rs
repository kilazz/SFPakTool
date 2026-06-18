use crate::UiLogger;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use encoding_rs::{WINDOWS_1251, WINDOWS_1252};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;

// -----------------------------------------------------------------------------
// MANIFEST STRUCTURES
// -----------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct ChunkManifest {
    file: String,
    id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag1: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    flag2: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurrence: Option<i16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comp_flag: Option<i16>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    c_type: Option<i16>,
}

#[derive(Serialize, Deserialize)]
struct Manifest {
    format: String,
    chunks: Vec<ChunkManifest>,
}

#[derive(PartialEq)]
enum ChunkFormat {
    Binary,
    Fixed566,
    StringTable,              // Format A
    DeveloperTable,           // Format C
    TableBased(usize, usize), // Format B
}

struct TableBasedEntry {
    id: u32,
    extra_bytes: Vec<u8>,
    strings: BTreeMap<usize, String>,
}

// -----------------------------------------------------------------------------
// TEXT ENCODING HELPERS
// -----------------------------------------------------------------------------

pub fn decode_windows(bytes: &[u8]) -> String {
    let (cow, _, had_errors) = WINDOWS_1252.decode(bytes);
    if had_errors {
        let (cow_cyrillic, _, _) = WINDOWS_1251.decode(bytes);
        cow_cyrillic.into_owned()
    } else {
        cow.into_owned()
    }
}

pub fn encode_windows(text: &str) -> Vec<u8> {
    let (cow, _, had_errors) = WINDOWS_1252.encode(text);
    if had_errors {
        let (cow_cyrillic, _, _) = WINDOWS_1251.encode(text);
        cow_cyrillic.into_owned()
    } else {
        cow.into_owned()
    }
}

// -----------------------------------------------------------------------------
// FORMAT DETECTION ENGINE
// -----------------------------------------------------------------------------

fn detect_format(data: &[u8]) -> ChunkFormat {
    if data.len() < 8 {
        return ChunkFormat::Binary;
    }

    // Detect Fixed 566 format
    if data.len() >= 566 && data.len().is_multiple_of(566) {
        let mut is_f566 = true;
        for i in 0..std::cmp::min(5, data.len() / 566) {
            if data[i * 566 + 565] != 0 {
                is_f566 = false;
                break;
            }
        }
        if is_f566 {
            return ChunkFormat::Fixed566;
        }
    }

    let mut cursor = Cursor::new(data);
    let count = cursor.read_u32::<LittleEndian>().unwrap_or(0);
    if count == 0 || count > 200_000 {
        return ChunkFormat::Binary;
    }

    // Detect Developer Table (Format C)
    let mut is_c = true;
    let mut offset = 4;
    for _ in 0..count {
        if offset + 6 > data.len() || data[offset] != 0x02 {
            is_c = false;
            break;
        }
        offset += 6;
        if offset + 4 > data.len() {
            is_c = false;
            break;
        }

        let mut len_cursor = Cursor::new(&data[offset..offset + 4]);
        let name_len = len_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if name_len > 100_000 || offset + 4 + name_len > data.len() {
            is_c = false;
            break;
        }
        offset += 4 + name_len;

        if offset + 4 > data.len() {
            is_c = false;
            break;
        }

        let mut key_cursor = Cursor::new(&data[offset..offset + 4]);
        let key_len = key_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if key_len > 1000 || offset + 4 + key_len > data.len() {
            is_c = false;
            break;
        }
        offset += 4 + key_len;
    }
    if is_c && offset == data.len() {
        return ChunkFormat::DeveloperTable;
    }

    // Detect String Table (Format A)
    let mut is_a = true;
    offset = 4;
    for _ in 0..count {
        if offset + 5 > data.len() || data[offset] != 0x01 {
            is_a = false;
            break;
        }
        offset += 1;

        let mut key_cursor = Cursor::new(&data[offset..offset + 4]);
        let key_len = key_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if key_len > 1000 || offset + 4 + key_len > data.len() {
            is_a = false;
            break;
        }
        offset += 4 + key_len;

        if offset + 4 > data.len() {
            is_a = false;
            break;
        }

        let mut text_cursor = Cursor::new(&data[offset..offset + 4]);
        let text_len = text_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
        if text_len > 100_000 || offset + 4 + (text_len * 2) > data.len() {
            is_a = false;
            break;
        }
        offset += 4 + (text_len * 2);
    }
    if is_a && offset == data.len() {
        return ChunkFormat::StringTable;
    }

    // Detect Table Based (Format B)
    for e in 0..17 {
        for n in 1..6 {
            let mut is_b = true;
            offset = 4;
            for _ in 0..count {
                if offset + 4 + e > data.len() {
                    is_b = false;
                    break;
                }
                offset += 4 + e;
                for _ in 0..n {
                    if offset + 4 > data.len() {
                        is_b = false;
                        break;
                    }
                    let mut str_cursor = Cursor::new(&data[offset..offset + 4]);
                    let str_len =
                        str_cursor.read_u32::<LittleEndian>().unwrap_or(0xFFFFFF) as usize;
                    if str_len > 100_000 || offset + 4 + (str_len * 2) > data.len() {
                        is_b = false;
                        break;
                    }
                    offset += 4 + (str_len * 2);
                }
            }
            if is_b && offset == data.len() {
                return ChunkFormat::TableBased(n, e);
            }
        }
    }

    ChunkFormat::Binary
}

// -----------------------------------------------------------------------------
// TEXT EXPORT / IMPORT ENGINE
// -----------------------------------------------------------------------------

fn export_text(data: &[u8], json_path: &Path, format: ChunkFormat) -> io::Result<()> {
    let mut texts: BTreeMap<String, String> = BTreeMap::new();

    if format == ChunkFormat::Fixed566 {
        let mut offset = 0;
        while offset + 566 <= data.len() {
            let block = &data[offset..offset + 566];
            let str_id = Cursor::new(&block[0..4]).read_u32::<LittleEndian>()?;
            let mut text_bytes = &block[54..566];
            if let Some(null_idx) = text_bytes.iter().position(|&b| b == 0) {
                text_bytes = &text_bytes[..null_idx];
            }
            texts.insert(
                format!("f566_{}_{}", offset, str_id),
                decode_windows(text_bytes),
            );
            offset += 566;
        }
    } else {
        let mut cursor = Cursor::new(data);
        let count = cursor.read_u32::<LittleEndian>()?;
        let mut offset = 4;

        match format {
            ChunkFormat::StringTable => {
                for _ in 0..count {
                    offset += 1;
                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let key_len = c.read_u32::<LittleEndian>()? as usize;
                    offset += 4;
                    let key = String::from_utf8_lossy(&data[offset..offset + key_len]).into_owned();
                    offset += key_len;

                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let text_len = c.read_u32::<LittleEndian>()? as usize;
                    offset += 4;
                    let u16_slice: Vec<u16> = data[offset..offset + text_len * 2]
                        .chunks_exact(2)
                        .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                        .collect();
                    let text = String::from_utf16_lossy(&u16_slice);
                    offset += text_len * 2;
                    texts.insert(key, text);
                }
            }
            ChunkFormat::DeveloperTable => {
                for i in 0..count {
                    offset += 1;
                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let id_val = c.read_u32::<LittleEndian>()?;
                    offset += 4;

                    let flag = data[offset];
                    offset += 1;

                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let name_len = c.read_u32::<LittleEndian>()? as usize;
                    offset += 4;
                    let name = decode_windows(&data[offset..offset + name_len]);
                    offset += name_len;

                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let key_len = c.read_u32::<LittleEndian>()? as usize;
                    offset += 4;
                    let key_str = decode_windows(&data[offset..offset + key_len]);
                    offset += key_len;

                    texts.insert(format!("{}_{}_{}_{}", i, id_val, flag, key_str), name);
                }
            }
            ChunkFormat::TableBased(num_strings, extra_bytes) => {
                for i in 0..count {
                    let mut c = Cursor::new(&data[offset..offset + 4]);
                    let id_val = c.read_u32::<LittleEndian>()?;
                    offset += 4;

                    let extra_slice = &data[offset..offset + extra_bytes];
                    let extra_hex: String =
                        extra_slice.iter().map(|b| format!("{:02x}", b)).collect();
                    offset += extra_bytes;

                    for s in 0..num_strings {
                        let mut c = Cursor::new(&data[offset..offset + 4]);
                        let str_len = c.read_u32::<LittleEndian>()? as usize;
                        offset += 4;

                        let u16_slice: Vec<u16> = data[offset..offset + str_len * 2]
                            .chunks_exact(2)
                            .map(|ch| u16::from_le_bytes([ch[0], ch[1]]))
                            .collect();
                        let text = String::from_utf16_lossy(&u16_slice);
                        offset += str_len * 2;

                        texts.insert(format!("{}_{}_{}_str{}", i, id_val, extra_hex, s), text);
                    }
                }
            }
            _ => {}
        }
    }

    if !texts.is_empty() {
        let f = File::create(json_path)?;
        serde_json::to_writer_pretty(f, &texts)?;
    }

    Ok(())
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

fn import_text(json_path: &Path, chunk_path: &Path) -> io::Result<()> {
    let json_data = fs::read_to_string(json_path)?;
    let texts: BTreeMap<String, String> = serde_json::from_str(&json_data)?;
    if texts.is_empty() {
        return Ok(());
    }

    let mut is_table_based = false;
    let mut is_developer_table = false;
    let mut is_fixed_566 = false;
    let mut num_strings = 0;

    if let Some(first_key) = texts.keys().next() {
        if first_key.starts_with("f566_") {
            is_fixed_566 = true;
        } else {
            let parts: Vec<&str> = first_key.splitn(4, '_').collect();
            if parts.len() == 4
                && parts[0].parse::<u32>().is_ok()
                && parts[1].parse::<u32>().is_ok()
            {
                let str_idx_opt = if parts[3].starts_with("str") {
                    is_table_based = true;
                    let mut max_idx = 0;
                    for key in texts.keys() {
                        let k_parts: Vec<&str> = key.splitn(4, '_').collect();
                        if k_parts.len() == 4
                            && k_parts[3].starts_with("str")
                            && let Ok(str_idx) = k_parts[3][3..].parse::<usize>()
                        {
                            max_idx = max_idx.max(str_idx + 1);
                        }
                    }
                    Some(max_idx)
                } else {
                    is_developer_table = true;
                    None
                };
                if let Some(resolved_len) = str_idx_opt {
                    num_strings = resolved_len;
                }
            }
        }
    }

    if is_fixed_566 {
        let mut orig_data = fs::read(chunk_path)?;
        for (key, val) in &texts {
            if !key.starts_with("f566_") {
                continue;
            }
            let parts: Vec<&str> = key.split('_').collect();
            let offset = parts[1].parse::<usize>().unwrap();

            let mut text_bytes = encode_windows(val);
            if text_bytes.len() > 511 {
                text_bytes.truncate(511);
            }
            let mut padded = vec![0u8; 512];
            padded[..text_bytes.len()].copy_from_slice(&text_bytes);

            if offset + 566 <= orig_data.len() {
                orig_data[offset + 54..offset + 566].copy_from_slice(&padded);
            }
        }
        File::create(chunk_path)?.write_all(&orig_data)?;
        return Ok(());
    }

    let mut out = File::create(chunk_path)?;

    if is_developer_table {
        let mut entries: BTreeMap<u32, (u32, u8, String, String)> = BTreeMap::new();
        for (key, val) in &texts {
            let parts: Vec<&str> = key.splitn(4, '_').collect();
            let idx = parts[0].parse::<u32>().unwrap();
            let id_val = parts[1].parse::<u32>().unwrap();
            let flag = parts[2].parse::<u8>().unwrap();
            entries.insert(idx, (id_val, flag, val.clone(), parts[3].to_string()));
        }

        out.write_u32::<LittleEndian>(entries.len() as u32)?;
        for (_, (id_val, flag, name, dev_key)) in entries {
            out.write_u8(0x02)?;
            out.write_u32::<LittleEndian>(id_val)?;
            out.write_u8(flag)?;

            let name_enc = encode_windows(&name);
            out.write_u32::<LittleEndian>(name_enc.len() as u32)?;
            out.write_all(&name_enc)?;

            let key_enc = encode_windows(&dev_key);
            out.write_u32::<LittleEndian>(key_enc.len() as u32)?;
            out.write_all(&key_enc)?;
        }
    } else if is_table_based {
        let mut entries: BTreeMap<u32, TableBasedEntry> = BTreeMap::new();
        for (key, val) in &texts {
            let parts: Vec<&str> = key.splitn(4, '_').collect();
            let idx = parts[0].parse::<u32>().unwrap();
            let id_val = parts[1].parse::<u32>().unwrap();
            let extra_bytes = hex_to_bytes(parts[2]);
            let str_idx = parts[3][3..].parse::<usize>().unwrap();

            let entry = entries.entry(idx).or_insert_with(|| TableBasedEntry {
                id: id_val,
                extra_bytes,
                strings: BTreeMap::new(),
            });
            entry.strings.insert(str_idx, val.clone());
        }

        out.write_u32::<LittleEndian>(entries.len() as u32)?;
        for (_, entry) in entries {
            out.write_u32::<LittleEndian>(entry.id)?;
            out.write_all(&entry.extra_bytes)?;
            for s in 0..num_strings {
                let empty = String::new();
                let text_val = entry.strings.get(&s).unwrap_or(&empty);
                let utf16: Vec<u16> = text_val.encode_utf16().collect();

                out.write_u32::<LittleEndian>(utf16.len() as u32)?;
                for &u in &utf16 {
                    out.write_u16::<LittleEndian>(u)?;
                }
            }
        }
    } else {
        out.write_u32::<LittleEndian>(texts.len() as u32)?;
        for (key, val) in texts {
            out.write_u8(0x01)?;
            let key_bytes = key.as_bytes();
            out.write_u32::<LittleEndian>(key_bytes.len() as u32)?;
            out.write_all(key_bytes)?;

            let utf16: Vec<u16> = val.encode_utf16().collect();
            out.write_u32::<LittleEndian>(utf16.len() as u32)?;
            for u in utf16 {
                out.write_u16::<LittleEndian>(u)?;
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// MAIN UNPACK / PACK LOGIC
// -----------------------------------------------------------------------------

pub fn unpack_all(input: &Path, out_dir: &Path, logger: &UiLogger) -> io::Result<()> {
    fs::create_dir_all(out_dir)?;
    let json_dir = out_dir.join("texts_json");
    fs::create_dir_all(&json_dir)?;

    let mut data = Vec::new();
    File::open(input)?.read_to_end(&mut data)?;

    if data.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid CFF Signature!",
        ));
    }

    let mut fmt_type = "sf2".to_string();
    let sig = &data[0..4];
    if sig == b"\x02\xc5r\xdd" {
        fmt_type = "sf1".to_string();
        logger.log("[*] Detected SpellForce 1 CFF container.");
    } else if sig == b"\x12\xdd\x72\xdd" {
        let h2 = Cursor::new(&data[4..8])
            .read_u32::<LittleEndian>()
            .unwrap_or(0);
        let h3 = Cursor::new(&data[8..12])
            .read_u32::<LittleEndian>()
            .unwrap_or(0);
        let h4 = Cursor::new(&data[12..16])
            .read_u32::<LittleEndian>()
            .unwrap_or(0);
        let h5 = Cursor::new(&data[16..20])
            .read_u32::<LittleEndian>()
            .unwrap_or(0);
        if h2 == 2 && h3 == 2 && h4 == 1 && h5 == 0 {
            fmt_type = "sf1".to_string();
            logger.log("[*] Detected SpellForce 1 CFF (Platinum Edition).");
        } else if data.len() > 36 {
            let cs_2 = Cursor::new(&data[26..28])
                .read_u16::<LittleEndian>()
                .unwrap_or(1);
            let us_2 = Cursor::new(&data[30..34])
                .read_u32::<LittleEndian>()
                .unwrap_or(0);
            if cs_2 == 0 && (us_2 as usize) > data.len() {
                fmt_type = "sf1".to_string();
                logger.log("[*] Detected SpellForce 1 CFF (Heuristics).");
            } else {
                logger.log("[*] Detected SpellForce 2 CFF container.");
            }
        } else {
            logger.log("[*] Detected SpellForce 2 CFF container.");
        }
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid CFF Signature!",
        ));
    }

    File::create(out_dir.join("header.bin"))?.write_all(&data[0..20])?;

    let mut manifest = Manifest {
        format: fmt_type.clone(),
        chunks: Vec::new(),
    };
    let mut cursor = Cursor::new(&data);
    cursor.set_position(20);

    let mut chunk_idx = 0;
    let mut text_extracted = 0;

    while (cursor.position() as usize) < data.len() {
        if chunk_idx > 0 && chunk_idx % 500 == 0 {
            logger.log(&format!("Unpacked {} chunks...", chunk_idx));
        }

        let mut uncomp_data = Vec::new();
        let chunk_manifest: ChunkManifest;

        if fmt_type == "sf1" {
            if cursor.position() as usize + 12 > data.len() {
                break;
            }
            let id = cursor.read_i16::<LittleEndian>()? as u32;
            let occurrence = cursor.read_i16::<LittleEndian>()?;
            let comp_flag = cursor.read_i16::<LittleEndian>()?;
            let comp_size = cursor.read_i32::<LittleEndian>()?;
            let c_type = cursor.read_i16::<LittleEndian>()?;

            if comp_flag == 0 {
                let mut buf = vec![0u8; comp_size as usize];
                cursor.read_exact(&mut buf)?;
                uncomp_data = buf;
            } else {
                if cursor.position() as usize + 4 > data.len() {
                    break;
                }
                let _uncomp_size = cursor.read_i32::<LittleEndian>()?;
                let mut comp_data = vec![0u8; comp_size as usize];
                cursor.read_exact(&mut comp_data)?;

                let mut decoder = ZlibDecoder::new(comp_data.as_slice());
                if decoder.read_to_end(&mut uncomp_data).is_err() {
                    uncomp_data = comp_data;
                }
            }

            chunk_manifest = ChunkManifest {
                file: format!("chunk_{}.dat", chunk_idx),
                id,
                flag1: None,
                flag2: None,
                occurrence: Some(occurrence),
                comp_flag: Some(comp_flag),
                c_type: Some(c_type),
            };
        } else {
            if cursor.position() as usize + 16 > data.len() {
                break;
            }
            let id = cursor.read_u32::<LittleEndian>()?;
            let flag1 = cursor.read_u16::<LittleEndian>()?;
            let comp_size = cursor.read_u32::<LittleEndian>()?;
            let flag2 = cursor.read_u16::<LittleEndian>()?;
            let _uncomp_size = cursor.read_u32::<LittleEndian>()?;

            let mut comp_data = vec![0u8; comp_size as usize];
            cursor.read_exact(&mut comp_data)?;

            let mut decoder = ZlibDecoder::new(comp_data.as_slice());
            if decoder.read_to_end(&mut uncomp_data).is_err() {
                uncomp_data = comp_data;
            }

            chunk_manifest = ChunkManifest {
                file: format!("chunk_{}.dat", chunk_idx),
                id,
                flag1: Some(flag1),
                flag2: Some(flag2),
                occurrence: None,
                comp_flag: None,
                c_type: None,
            };
        }

        let chunk_name = chunk_manifest.file.clone();
        let chunk_path = out_dir.join(&chunk_name);
        File::create(&chunk_path)?.write_all(&uncomp_data)?;
        manifest.chunks.push(chunk_manifest);

        let fmt = detect_format(&uncomp_data);
        if fmt != ChunkFormat::Binary {
            let json_path = json_dir.join(format!("chunk_{}_strings.json", chunk_idx));
            if export_text(&uncomp_data, &json_path, fmt).is_ok() {
                text_extracted += 1;
            }
        }
        chunk_idx += 1;
    }

    let manifest_file = File::create(out_dir.join("manifest.json"))?;
    serde_json::to_writer_pretty(manifest_file, &manifest)?;

    logger.log(&format!("Unpacked {} chunks successfully.", chunk_idx));
    logger.log(&format!(
        "Exported {} text datasets to JSON.",
        text_extracted
    ));

    Ok(())
}

pub fn pack_all(
    in_dir: &Path,
    out_file: &Path,
    comp_level: u32,
    logger: &UiLogger,
) -> io::Result<()> {
    let manifest_path = in_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "manifest.json not found!",
        ));
    }

    let manifest_data = fs::read_to_string(manifest_path)?;
    let manifest: Manifest = serde_json::from_str(&manifest_data)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let fmt_type = manifest.format.clone();
    let json_dir = in_dir.join("texts_json");

    if let Ok(entries) = fs::read_dir(&json_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if let Some(file_name) = path.file_name().and_then(|n| n.to_str())
                && file_name.starts_with("chunk_")
                && file_name.ends_with("_strings.json")
            {
                let parts: Vec<&str> = file_name.split('_').collect();
                if let Some(&chunk_idx) = parts.get(1) {
                    let target_dat = in_dir.join(format!("chunk_{}.dat", chunk_idx));
                    if target_dat.exists()
                        && let Err(e) = import_text(&path, &target_dat)
                    {
                        logger.log(&format!("[!] Error compiling {}: {}", file_name, e));
                    }
                }
            }
        }
    }

    let mut out = File::create(out_file)?;

    let header_path = in_dir.join("header.bin");
    if header_path.exists() {
        let mut header = Vec::new();
        File::open(header_path)?.read_to_end(&mut header)?;
        out.write_all(&header)?;
    } else {
        if fmt_type == "sf1" {
            out.write_i32::<LittleEndian>(-579674862)?;
            out.write_all(&[0u8; 16])?;
        } else {
            out.write_all(b"\x12\xdd\x72\xdd")?;
            out.write_all(&[0u8; 16])?;
        }
    }

    for (idx, chunk) in manifest.chunks.into_iter().enumerate() {
        if idx > 0 && idx % 500 == 0 {
            logger.log(&format!("Packed {} chunks...", idx));
        }

        let mut uncomp_data = Vec::new();
        let chunk_path = in_dir.join(&chunk.file);
        if !chunk_path.exists() {
            continue;
        }
        File::open(chunk_path)?.read_to_end(&mut uncomp_data)?;

        if fmt_type == "sf1" {
            let comp_flag = chunk.comp_flag.unwrap_or(1);
            let occurrence = chunk.occurrence.unwrap_or(0);
            let c_type = chunk.c_type.unwrap_or(0);

            if comp_flag == 0 {
                out.write_i16::<LittleEndian>(chunk.id as i16)?;
                out.write_i16::<LittleEndian>(occurrence)?;
                out.write_i16::<LittleEndian>(0)?;
                out.write_i32::<LittleEndian>(uncomp_data.len() as i32)?;
                out.write_i16::<LittleEndian>(c_type)?;
                out.write_all(&uncomp_data)?;
            } else {
                let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(comp_level));
                encoder.write_all(&uncomp_data)?;
                let comp_data = encoder.finish()?;

                out.write_i16::<LittleEndian>(chunk.id as i16)?;
                out.write_i16::<LittleEndian>(occurrence)?;
                out.write_i16::<LittleEndian>(comp_flag)?;
                out.write_i32::<LittleEndian>(comp_data.len() as i32)?;
                out.write_i16::<LittleEndian>(c_type)?;
                out.write_i32::<LittleEndian>(uncomp_data.len() as i32)?;
                out.write_all(&comp_data)?;
            }
        } else {
            let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(comp_level));
            encoder.write_all(&uncomp_data)?;
            let comp_data = encoder.finish()?;

            out.write_u32::<LittleEndian>(chunk.id)?;
            out.write_u16::<LittleEndian>(chunk.flag1.unwrap_or(0))?;
            out.write_u32::<LittleEndian>(comp_data.len() as u32)?;
            out.write_u16::<LittleEndian>(chunk.flag2.unwrap_or(0))?;
            out.write_u32::<LittleEndian>(uncomp_data.len() as u32)?;
            out.write_all(&comp_data)?;
        }
    }

    logger.log("CFF successfully packed and compiled!");
    Ok(())
}
