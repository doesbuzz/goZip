// ghzip_cli.go
// Single-file Huffman + AES-GCM archiver with TUI-like CLI.
// Only uses Go stdlib.

package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Archive format (high level):
// [4 bytes magic] "GHA1"
// [1 byte version] 1
// [12 bytes nonce for AES-GCM]
// [256 * 8 bytes frequency table (uint64 little-endian) ]
// [8 bytes compressed ciphertext length (uint64)]
// [ciphertext bytes (AES-GCM output; includes tag)]
//
// Decrypted compressed payload is a concatenation of file entries:
// For each file:
//   [2 bytes filename length uint16]
//   [filename bytes]
//   [8 bytes original size uint64]
//   [original file bytes]

const magic = "GHA1"
const version = 1

func main() {
	// Flags for non-interactive use
	createFlag := flag.Bool("c", false, "create archive (non-interactive)")
	extractFlag := flag.Bool("x", false, "extract archive (non-interactive)")
	listFlag := flag.Bool("l", false, "list archive contents (non-interactive)")
	inPath := flag.String("in", "", "input path (for create) or archive (for extract/list)")
	outPath := flag.String("out", "", "output archive (for create) or destination dir (for extract)")
	pass := flag.String("pass", "", "password (optional; if empty you'll be prompted)")
	flag.Parse()

	// If any of create/extract/list provided, run non-interactive
	if *createFlag || *extractFlag || *listFlag {
		pw := *pass
		if pw == "" {
			pw = promptPassword("Password: ")
		}
		if *createFlag {
			if *inPath == "" || *outPath == "" {
				fmt.Println("create requires -in <file-or-dir> and -out <archive>")
				return
			}
			showBox("Creating archive", fmt.Sprintf("Input: %s\nOutput: %s", *inPath, *outPath))
			if err := createArchive(*inPath, *outPath, pw, true); err != nil {
				fail("Create failed: %v", err)
			}
			showOK("Archive created: %s", *outPath)
			return
		}
		if *listFlag {
			if *inPath == "" {
				fmt.Println("list requires -in <archive>")
				return
			}
			showBox("Listing archive", fmt.Sprintf("Archive: %s", *inPath))
			names, err := listArchive(*inPath, pw)
			if err != nil {
				fail("List failed: %v", err)
			}
			fmt.Println()
			fmt.Println("Files in archive:")
			for _, n := range names {
				fmt.Println("  -", n)
			}
			return
		}
		if *extractFlag {
			if *inPath == "" {
				fmt.Println("extract requires -in <archive>")
				return
			}
			dest := *outPath
			if dest == "" {
				dest = "."
			}
			showBox("Extracting archive", fmt.Sprintf("Archive: %s\nDestination: %s", *inPath, dest))
			if err := extractArchive(*inPath, dest, pw, true); err != nil {
				fail("Extract failed: %v", err)
			}
			showOK("Extracted to: %s", dest)
			return
		}
	}

	// Interactive TUI-like menu
	reader := bufio.NewReader(os.Stdin)
	for {
		clearScreen()
		drawTitle("ghzip — Huffman + AES-GCM (TUI CLI)")
		fmt.Println()
		drawMenuBox([]string{
			"[1] Create archive",
			"[2] List archive",
			"[3] Extract archive",
			"[q] Quit",
		})
		fmt.Print("\nChoose an option: ")
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)
		switch choice {
		case "1":
			fmt.Print("Path (file or directory) to archive: ")
			inp, _ := reader.ReadString('\n')
			inp = strings.TrimSpace(inp)
			fmt.Print("Output archive path (e.g. archive.gha): ")
			outp, _ := reader.ReadString('\n')
			outp = strings.TrimSpace(outp)
			pw := promptPassword("Password: ")
			showBox("Creating archive", fmt.Sprintf("Input: %s\nOutput: %s", inp, outp))
			err := createArchive(inp, outp, pw, false)
			if err != nil {
				fail("Create failed: %v", err)
			} else {
				showOK("Archive created: %s", outp)
			}
			pause()
		case "2":
			fmt.Print("Archive path: ")
			inp, _ := reader.ReadString('\n')
			inp = strings.TrimSpace(inp)
			pw := promptPassword("Password: ")
			showBox("Listing archive", fmt.Sprintf("Archive: %s", inp))
			names, err := listArchive(inp, pw)
			if err != nil {
				fail("List failed: %v", err)
				pause()
				continue
			}
			fmt.Println()
			fmt.Println("Files in archive:")
			for _, n := range names {
				fmt.Println("  -", n)
			}
			pause()
		case "3":
			fmt.Print("Archive path: ")
			inp, _ := reader.ReadString('\n')
			inp = strings.TrimSpace(inp)
			fmt.Print("Destination directory (default .): ")
			dest, _ := reader.ReadString('\n')
			dest = strings.TrimSpace(dest)
			if dest == "" {
				dest = "."
			}
			pw := promptPassword("Password: ")
			showBox("Extracting archive", fmt.Sprintf("Archive: %s\nDestination: %s", inp, dest))
			err := extractArchive(inp, dest, pw, false)
			if err != nil {
				fail("Extract failed: %v", err)
			} else {
				showOK("Extracted to: %s", dest)
			}
			pause()
		case "q", "Q":
			fmt.Println("Goodbye.")
			return
		default:
			fmt.Println("Unknown option.")
			time.Sleep(700 * time.Millisecond)
		}
	}
}

// ---------- Small TUI helpers (ASCII boxes, progress) ------------

func clearScreen() {
	// ANSI clear
	fmt.Print("\033[H\033[2J")
}

func drawTitle(s string) {
	fmt.Println("+------------------------------------------------------------+")
	center := (60 - len(s)) / 2
	if center < 0 {
		center = 0
	}
	fmt.Printf("|%s%s%s|\n", strings.Repeat(" ", 2), strings.Repeat(" ", center)+s, strings.Repeat(" ", 60-len(s)-center-2))
	fmt.Println("+------------------------------------------------------------+")
}

func drawMenuBox(lines []string) {
	fmt.Println("+------------------------------------------------------------+")
	for _, l := range lines {
		fmt.Printf("|  %-56s |\n", l)
	}
	fmt.Println("+------------------------------------------------------------+")
}

func showBox(title, body string) {
	clearScreen()
	fmt.Println("+------------------------------------------------------------+")
	fmt.Printf("| %-54s |\n", title)
	fmt.Println("+------------------------------------------------------------+")
	for _, line := range strings.Split(body, "\n") {
		if len(line) > 56 {
			// wrap
			for i := 0; i < len(line); i += 56 {
				end := i + 56
				if end > len(line) {
					end = len(line)
				}
				fmt.Printf("|  %-56s |\n", line[i:end])
			}
		} else {
			fmt.Printf("|  %-56s |\n", line)
		}
	}
	fmt.Println("+------------------------------------------------------------+")
}

func showOK(format string, args ...interface{}) {
	fmt.Println()
	fmt.Printf("[ OK ] "+format+"\n", args...)
}

func fail(format string, args ...interface{}) {
	fmt.Println()
	fmt.Printf("[FAIL] "+format+"\n", args...)
}

func pause() {
	fmt.Println("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
}

func promptPassword(prompt string) string {
	// For portability and pure-stdlib, we do a plain-text prompt.
	// Advanced no-echo would require syscalls or golang.org/x/term (not allowed here).
	fmt.Print(prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(line)
}

func showProgress(prefix string, done, total int64) {
	// simple ASCII progress bar
	const width = 40
	var pct int
	if total > 0 {
		pct = int((done * 100) / total)
	} else {
		pct = 0
	}
	filled := (pct * width) / 100
	bar := strings.Repeat("=", filled) + strings.Repeat(" ", width-filled)
	fmt.Printf("\r%s [%s] %3d%%", prefix, bar, pct)
	if done >= total {
		fmt.Println()
	}
}

// ---------------------- Archive operations -------------------------

func createArchive(inputPath, outArchive, password string, quiet bool) error {
	// Walk input path
	files := []struct {
		relPath string
		absPath string
		info    fs.FileInfo
	}{}

	fi, err := os.Stat(inputPath)
	if err != nil {
		return err
	}
	baseDir := filepath.Dir(inputPath)
	if fi.IsDir() {
		baseDir = inputPath
		err := filepath.WalkDir(inputPath, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(baseDir, path)
			if err != nil {
				return err
			}
			files = append(files, struct {
				relPath string
				absPath string
				info    fs.FileInfo
			}{relPath: rel, absPath: path, info: info})
			return nil
		})
		if err != nil {
			return err
		}
	} else {
		rel := filepath.Base(inputPath)
		files = append(files, struct {
			relPath string
			absPath string
			info    fs.FileInfo
		}{relPath: rel, absPath: inputPath, info: fi})
	}

	if !quiet {
		fmt.Printf("Found %d file(s) to archive.\n", len(files))
	}

	// Build payload
	var payload bytes.Buffer
	var totalBytes int64
	for _, f := range files {
		data, err := os.ReadFile(f.absPath)
		if err != nil {
			return err
		}
		totalBytes += int64(len(data))
		nameBytes := []byte(filepath.ToSlash(f.relPath))
		if len(nameBytes) > 65535 {
			return fmt.Errorf("filename too long: %s", f.relPath)
		}
		if err := binary.Write(&payload, binary.LittleEndian, uint16(len(nameBytes))); err != nil {
			return err
		}
		if _, err := payload.Write(nameBytes); err != nil {
			return err
		}
		if err := binary.Write(&payload, binary.LittleEndian, uint64(len(data))); err != nil {
			return err
		}
		if _, err := payload.Write(data); err != nil {
			return err
		}
		if !quiet {
			showProgress("Packing", int64(payload.Len()), totalBytes+int64(len(files))*10)
		}
	}
	if !quiet {
		fmt.Printf("Payload size (bytes): %d\n", payload.Len())
	}

	// Frequency table
	dataBytes := payload.Bytes()
	var freq [256]uint64
	for _, b := range dataBytes {
		freq[b]++
	}

	// Huffman compress
	if !quiet {
		fmt.Println("Building Huffman tree and compressing...")
	}
	compressed, err := huffmanCompress(dataBytes, freq)
	if err != nil {
		return err
	}
	if !quiet {
		fmt.Printf("Compressed size: %d bytes (ratio %.2f%%)\n", len(compressed), 100.0*float64(len(compressed))/float64(len(dataBytes)))
	}

	// Encrypt compressed bytes with AES-GCM
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	if !quiet {
		fmt.Println("Encrypting payload...")
	}
	ciphertext := gcm.Seal(nil, nonce, compressed, nil)

	// Write archive file
	outf, err := os.Create(outArchive)
	if err != nil {
		return err
	}
	defer outf.Close()

	if _, err := outf.Write([]byte(magic)); err != nil {
		return err
	}
	if _, err := outf.Write([]byte{version}); err != nil {
    return err
	}
	if _, err := outf.Write(nonce); err != nil {
		return err
	}
	for i := 0; i < 256; i++ {
		if err := binary.Write(outf, binary.LittleEndian, freq[i]); err != nil {
			return err
		}
	}
	if err := binary.Write(outf, binary.LittleEndian, uint64(len(ciphertext))); err != nil {
		return err
	}
	if _, err := outf.Write(ciphertext); err != nil {
		return err
	}
	if !quiet {
		fmt.Println("Write completed.")
	}
	return nil
}

func listArchive(archivePath, password string) ([]string, error) {
	payload, err := readAndDecryptArchive(archivePath, password)
	if err != nil {
		return nil, err
	}
	var names []string
	r := bytes.NewReader(payload)
	for {
		var nameLen uint16
		 if err := binary.Read(r, binary.LittleEndian, &nameLen); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		nb := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nb); err != nil {
			return nil, err
		}
		var origSize uint64
		if err := binary.Read(r, binary.LittleEndian, &origSize); err != nil {
			return nil, err
		}
		// skip file bytes
		if _, err := r.Seek(int64(origSize), io.SeekCurrent); err != nil {
			return nil, err
		}
		names = append(names, string(nb))
	}
	return names, nil
}

func extractArchive(archivePath, destDir, password string, quiet bool) error {
	payload, err := readAndDecryptArchive(archivePath, password)
	if err != nil {
		return err
	}
	r := bytes.NewReader(payload)
	var extracted int
	var totalBytes int64
	// first pass to compute total for progress (sum of sizes)
	{
		r2 := bytes.NewReader(payload)
		for {
			var nameLen uint16
			if err := binary.Read(r2, binary.LittleEndian, &nameLen); err != nil {
				if err == io.EOF {
					break
				}
				return err
			}
			if _, err := r2.Seek(int64(nameLen), io.SeekCurrent); err != nil {
				return err
			}
			var origSize uint64
			if err := binary.Read(r2, binary.LittleEndian, &origSize); err != nil {
				return err
			}
			totalBytes += int64(origSize)
			if _, err := r2.Seek(int64(origSize), io.SeekCurrent); err != nil {
				return err
			}
		}
	}

	var doneBytes int64
	for {
		var nameLen uint16
		if err := binary.Read(r, binary.LittleEndian, &nameLen); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		nb := make([]byte, nameLen)
		if _, err := io.ReadFull(r, nb); err != nil {
			return err
		}
		var origSize uint64
		if err := binary.Read(r, binary.LittleEndian, &origSize); err != nil {
			return err
		}
		data := make([]byte, origSize)
		if _, err := io.ReadFull(r, data); err != nil {
			return err
		}
		target := filepath.Join(destDir, filepath.FromSlash(string(nb)))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			return err
		}
		extracted++
		doneBytes += int64(len(data))
		if !quiet {
			showProgress("Extracting", doneBytes, totalBytes)
		}
	}
	if !quiet {
		fmt.Printf("Extracted %d files.\n", extracted)
	}
	return nil
}

func readAndDecryptArchive(path, password string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m := make([]byte, len(magic))
	if _, err := io.ReadFull(f, m); err != nil {
		return nil, err
	}
	if string(m) != magic {
		return nil, fmt.Errorf("not a ghzip archive (magic mismatch)")
	}
	ver := make([]byte, 1)
	if _, err := io.ReadFull(f, ver); err != nil {
		return nil, err
	}
	if ver[0] != version {
		return nil, fmt.Errorf("unsupported version: %d", ver[0])
	}
	key := sha256.Sum256([]byte(password))
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(f, nonce); err != nil {
		return nil, err
	}
	var freq [256]uint64
	for i := 0; i < 256; i++ {
		if err := binary.Read(f, binary.LittleEndian, &freq[i]); err != nil {
			return nil, err
		}
	}
	var clen uint64
	if err := binary.Read(f, binary.LittleEndian, &clen); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, clen)
	if _, err := io.ReadFull(f, ciphertext); err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	data, err := huffmanDecompress(plain, freq)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// ---------------------- Huffman compression -----------------------

// node and heap for building Huffman tree
type node struct {
	b     byte
	freq  uint64
	left  *node
	right *node
}

type nodeHeap []*node

func (h nodeHeap) Len() int           { return len(h) }
func (h nodeHeap) Less(i, j int) bool { return h[i].freq < h[j].freq }
func (h nodeHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *nodeHeap) Push(x interface{}) {
	*h = append(*h, x.(*node))
}
func (h *nodeHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func buildTree(freq [256]uint64) *node {
	h := &nodeHeap{}
	for b, f := range freq {
		if f > 0 {
			heap.Push(h, &node{b: byte(b), freq: f})
		}
	}
	if h.Len() == 0 {
		return nil
	}
	if h.Len() == 1 {
		only := heap.Pop(h).(*node)
		root := &node{freq: only.freq, left: only}
		return root
	}
	heap.Init(h)
	for h.Len() > 1 {
		a := heap.Pop(h).(*node)
		b := heap.Pop(h).(*node)
		parent := &node{freq: a.freq + b.freq, left: a, right: b}
		heap.Push(h, parent)
	}
	return heap.Pop(h).(*node)
}

func buildCodes(root *node) map[byte]string {
	codeMap := make(map[byte]string)
	if root == nil {
		return codeMap
	}
	var dfs func(n *node, prefix string)
	dfs = func(n *node, prefix string) {
		if n == nil {
			return
		}
		if n.left == nil && n.right == nil {
			codeMap[n.b] = prefix
			return
		}
		dfs(n.left, prefix+"0")
		dfs(n.right, prefix+"1")
	}
	// single-symbol special-case
	if root.left != nil && root.right == nil && root.left.left == nil && root.left.right == nil {
		codeMap[root.left.b] = "0"
		return codeMap
	}
	dfs(root, "")
	return codeMap
}

type bitWriter struct {
	buf bytes.Buffer
	cur byte
	n   uint8
}

func (w *bitWriter) WriteBits(bitstr string) {
	for i := 0; i < len(bitstr); i++ {
		if bitstr[i] == '1' {
			w.cur |= 1 << (7 - w.n)
		}
		w.n++
		if w.n == 8 {
			w.buf.WriteByte(w.cur)
			w.cur = 0
			w.n = 0
		}
	}
}

func (w *bitWriter) Finish() []byte {
	if w.n > 0 {
		w.buf.WriteByte(w.cur)
	}
	return w.buf.Bytes()
}

func huffmanCompress(data []byte, freq [256]uint64) ([]byte, error) {
	root := buildTree(freq)
	if root == nil {
		return nil, nil
	}
	codes := buildCodes(root)
	bw := &bitWriter{}
	for _, b := range data {
		bs, ok := codes[b]
		if !ok {
			return nil, fmt.Errorf("no code for byte %v", b)
		}
		bw.WriteBits(bs)
	}
	return bw.Finish(), nil
}

type bitReader struct {
	data []byte
	pos  int
	bit  uint8
}

func newBitReader(b []byte) *bitReader {
	return &bitReader{data: b, pos: 0, bit: 0}
}

func (r *bitReader) readBit() (int, error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	cur := r.data[r.pos]
	v := (cur >> (7 - r.bit)) & 1
	r.bit++
	if r.bit == 8 {
		r.bit = 0
		r.pos++
	}
	return int(v), nil
}

func huffmanDecompress(comp []byte, freq [256]uint64) ([]byte, error) {
	root := buildTree(freq)
	if root == nil {
		return nil, nil
	}
	// single-symbol
	if root.left != nil && root.right == nil && root.left.left == nil && root.left.right == nil {
		only := root.left.b
		var total uint64
		for _, v := range freq {
			total += v
		}
		out := bytes.Repeat([]byte{only}, int(total))
		return out, nil
	}
	br := newBitReader(comp)
	var out bytes.Buffer
	for {
		n := root
		for n.left != nil || n.right != nil {
			bit, err := br.readBit()
			if err != nil {
				if err == io.EOF {
					return out.Bytes(), nil
				}
				return nil, err
			}
			if bit == 0 {
				n = n.left
			} else {
				n = n.right
			}
			if n == nil {
				return nil, errors.New("corrupt compressed data (walked to nil)")
			}
		}
		out.WriteByte(n.b)
	}
}
