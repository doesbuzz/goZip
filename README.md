# goZip

**goZip** is a single-binary archiver written entirely in Go’s standard library.  
It combines **Huffman compression** with **AES-GCM encryption**, providing a simple, secure, and portable alternative to tools like `zip` or `7z`.  

The program offers both:

- A **non-interactive CLI** (flags, good for scripting).  
- An **interactive TUI** (text-based UI in the terminal with menus, ASCII boxes, and progress bars).  

No third-party dependencies. No external libraries. Just Go stdlib.  

---

## ✨ Features

- ✅ Compresses using a **Huffman tree** (built per archive)  
- ✅ Encrypts with **AES-GCM** (key derived from SHA-256 of the password)  
- ✅ Archives files and directories (recursive)  
- ✅ Cross-platform: build once, run anywhere  
- ✅ Single binary (no runtime dependencies)  
- ✅ Interactive TUI menu for ease of use  
- ✅ Non-interactive CLI flags for scripting/automation  

---

## ⚙️ Build

Requires Go **1.18+**.

```bash
git clone https://github.com/yourname/goZip.git
cd goZip
go build -o goZip main.go
```

This will create a single binary called `goZip`.

---

## 🚀 Usage

goZip can be run in **two modes**:  

1. **Interactive (TUI)** → menu-driven, looks like a text-based GUI.  
2. **Non-interactive (CLI)** → uses flags, good for automation and scripting.  

---

### 1. Interactive Mode (TUI)

Run without any flags:

```bash
./goZip
```

You’ll get a menu like:

```
+------------------------------------------------------------+
|  goZip — Huffman + AES-GCM (TUI CLI)                       |
+------------------------------------------------------------+

+------------------------------------------------------------+
|  [1] Create archive                                        |
|  [2] List archive                                          |
|  [3] Extract archive                                       |
|  [q] Quit                                                  |
+------------------------------------------------------------+
```

Choose an option by typing the number or `q` to quit.  

- **Create archive** → prompts for input path, output file, password  
- **List archive** → shows contents of an archive (requires password if encrypted)  
- **Extract archive** → prompts for input archive, output directory, and password  

---

### 2. Non-interactive Mode (CLI Flags)

Flags allow you to use goZip in scripts or directly from the shell.

#### Create archive
```bash
./goZip -c -in myfolder -out archive.gha -pass "mypassword"
```

- `-c` → create archive  
- `-in` → input file or directory  
- `-out` → output archive file  
- `-pass` → password (optional, will prompt if omitted)  

#### List archive contents
```bash
./goZip -l -in archive.gha -pass "mypassword"
```

Lists the contents of the archive without extracting.  

#### Extract archive
```bash
./goZip -x -in archive.gha -out extracted/ -pass "mypassword"
```

Extracts the archive into the given output directory.  
If `-out` is omitted, files are extracted into the current directory.  

---

### Examples

#### Archive a single file
```bash
./goZip -c -in notes.txt -out notes.gha -pass "secret"
```

#### Archive a directory
```bash
./goZip -c -in project/ -out project.gha -pass "build2025"
```

#### Extract archive into current directory
```bash
./goZip -x -in project.gha -pass "build2025"
```

#### Extract into a custom folder
```bash
./goZip -x -in project.gha -out ./restore/ -pass "build2025"
```

#### List contents
```bash
./goZip -l -in project.gha -pass "build2025"
```

---

## 📦 Archive Format

Each `.gha` archive is structured as:

```
[4 bytes magic]          "GHA1"
[1 byte version]         1
[12 bytes nonce]         AES-GCM nonce
[256 * 8 bytes]          Huffman frequency table (uint64 each)
[8 bytes]                ciphertext length (uint64)
[ciphertext bytes]       AES-GCM encrypted compressed data
```

The decrypted & decompressed payload is a concatenation of file entries:

```
[2 bytes]   filename length (uint16)
[...bytes]  filename (UTF-8, slash-separated)
[8 bytes]   original size (uint64)
[...bytes]  file data
```

---

## ⚠️ Limitations

- Entire archive is built in memory before compression/encryption. Very large datasets may require lots of RAM.  
- Password input is **not hidden**. Hidden input would require OS-specific syscalls or `golang.org/x/term`.  
- File metadata (timestamps, permissions, symlinks) is **not preserved**. Only path + content.  
- Huffman compression is simple and not as efficient as LZ77/Deflate used by `zip`.  
