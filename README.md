# goZip

**goZip** is a single-binary archiver written entirely in Go’s standard library.  
It combines **Huffman compression** with **AES-GCM encryption**, providing a simple, secure, and portable alternative to tools like `zip` or `7z`.

The program offers:

- An **interactive TUI** (text-based UI in the terminal with menus, ASCII boxes, and progress bars).  

No third-party dependencies. No external libraries. Just Go stdlib.  

---

## Features

- ✅ Compresses using a **Huffman tree** (built per archive).
- ✅ Encrypts with **AES-GCM** (key derived from SHA-256 of the password).
- ✅ Archives files and directories (recursive).
- ✅ Cross-platform: build once, run anywhere.
- ✅ Single binary (no runtime dependencies).
- ✅ Interactive TUI menu for ease of use.
- ✅ Non-interactive CLI flags for scripting/automation.

---

## Build

Requires Go 1.18+
Recommened Go 1.25.1

```bash
git clone https://github.com/doesbuzz/goZip
cd goZip
go build -o goZip main.go
./goZip