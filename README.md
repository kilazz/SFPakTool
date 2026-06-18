## SFTool
A complete, high-performance, and lightweight modding and localization for **SpellForce 1/2** games.

## Features

### 📦 PAK Archive Management
* **Interactive TreeView:** Explore archive structures with a fully collapsible and expandable directory explorer.
* **Unpack:** Extract individual `.pak` files (auto-detects SpellForce 1/2 formats).
* **Pack:** Compile directories into valid SpellForce 2 `.pak` (zlib compression) or SpellForce 1 `.pak` (Stable Meta-Template injection or experimental Scratch mode).
* **Batch Operations:** Unpack all `.pak` archives in a folder, or pack folders ending in `_extracted` back to `.pak`.

### 🗄️ CFF Database Container Engine
* **Container Packaging:** Unpack `.cff` database containers into raw `.dat` chunks, and pack them back with customizable zlib compression.
* **Localization Exporter:** Auto-detect database schemas:
  * **Format A** (String Table - UTF-16LE),
  * **Format B** (Table-Based - Multi-string with parameters),
  * **Format C** (Developer Table - ANSI), and Fixed 566 structures.
* **Translation Suite:** Export text datasets to sorted JSON files, and compile edited JSONs back into binary chunks.

## How to Build & Run

### Prerequisites
* Install [Rust & Cargo](https://www.rust-lang.org/tools/install).

### Compilation
  * Clone the repository and open your terminal in the project's root directory.
  * To compile and run the application:
```
cargo run
cargo build --release
```
