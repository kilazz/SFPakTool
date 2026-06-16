## SFTool
A complete, high-performance, and lightweight modding suite for **SpellForce 1 & 2** games.

## Features

### 📦 PAK Archive Management
* **Interactive TreeView:** Explore archive structures with a fully collapsible and expandable directory explorer tree (with hover highlights and folder icons).
* **Unpack:** Extract individual `.pak` files (auto-detects legacy SpellForce 1 and SpellForce 2 formats).
* **Pack:** Compile directories into fully valid SpellForce 2 `.pak` archives with adjustable Zlib compression.
* **Batch Operations:**
  * Batch unpack all `.pak` archives found within a selected directory into individual folders.
  * Batch pack all subdirectories in a root folder (exclusively compiling folders ending in `_extracted` back to `.pak` files).

### 🗄️ CFF Database Container Engine (SF2)
* **Container Packaging:** Unpack `.cff` database containers into raw `.dat` chunks, and pack them back with customizable Zlib compression levels.
* **Localization Exporter:** Automatically detect binary database schema types:
  * **Format A** (String Table - UTF-16LE)
  * **Format B** (Table-Based - Multi-string UTF-16LE with metadata)
  * **Format C** (Developer Table - CP1252 / ANSI)
* **Translation Suite:** Export detected text datasets into clean, sorted JSON files for easy translation, and automatically compile edited JSON files back into binary database chunks.

## How to Build & Run

### Prerequisites
* Install [Rust & Cargo](https://www.rust-lang.org/tools/install).

### Compilation
1. Clone the repository and open your terminal in the project's root directory.
2. To compile and run the application:
```
cargo run
cargo build --release
```
