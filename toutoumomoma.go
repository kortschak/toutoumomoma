// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"crypto/md5"
	"debug/gosym"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

var (
	// ErrUnknownFormat is returned for files that are not recognized.
	ErrUnknownFormat = errors.New("unknown format")

	// ErrNotGoExecutable indicates a file was not a Go executable.
	ErrNotGoExecutable = errors.New("not a Go executable")
)

// File holds an executable object file.
type File struct {
	file
}

type file interface {
	isGoExecutable() (ok bool, err error)
	hasBuildID() (ok bool, err error)
	hasRealFiles() (ok bool, err error)
	importedSymbols() ([]string, error)
	goSymbols(stdlib bool) ([]string, error)
	sectionStats() ([]Section, error)
	io.Closer
}

// Open opens the file at at the provided path.
//
// If the file at path is not an ELF, Mach-O, plan9obj or PE format
// executable, Open will return ErrUnknownFormat. Files without
// execute permissions may be opened.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	file, err := NewFile(f)
	if err != nil {
		f.Close()
		return nil, err
	}
	return file, nil
}

// NewFile creates a new File for accessing a binary object in an underlying
// reader. The binary is expected to start at position 0 in the ReaderAt.
//
// If the in the reader is not an ELF, Mach-O, plan9obj or PE format
// executable, NewFile will return ErrUnknownFormat.
func NewFile(r io.ReaderAt) (*File, error) {
	var magic [4]byte
	_, err := r.ReadAt(magic[:], 0)
	if err != nil {
		if err == io.EOF {
			err = ErrUnknownFormat
		}
		return nil, err
	}
	switch {
	case bytes.Equal(magic[:], []byte("\x7FELF")):
		exe, err := openELF(r)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	case bytes.Equal(magic[:3], []byte("\xfe\xed\xfa")),
		bytes.Equal(magic[1:], []byte("\xfa\xed\xfe")):
		exe, err := openMachO(r)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	case bytes.Equal(magic[:2], []byte("MZ")):
		exe, err := openPE(r)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	case bytes.Equal(magic[:], []byte("\x00\x00\x01\xeb")),
		bytes.Equal(magic[:], []byte("\x00\x00\x8a\x97")),
		bytes.Equal(magic[:], []byte("\x00\x00\x06G")):
		exe, err := openPlan9(r)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	default:
		return nil, ErrUnknownFormat
	}
}

// Type returns the type of the executable object file. It will be one of,
// "ELF", "Mach-O", "Plan9" or "PE".
func (f *File) Type() string {
	switch f.file.(type) {
	case *elfFile:
		return "ELF"
	case *machoFile:
		return "Mach-O"
	case *plan9File:
		return "Plan9"
	case *peFile:
		return "PE"
	default:
		panic("unreachable")
	}
}

// Close closes the file. If the File was created using NewFile directly
// instead of Open, Close has no effect.
func (f *File) Close() error {
	return f.file.Close()
}

// Stripped examines the file and returns whether it is likely to be a Go
// executable that has had its symbols stripped.
func (f *File) Stripped() (sneaky bool, err error) {
	isGo, err := f.isGoExecutable()
	if err != nil {
		return false, err
	}
	if !isGo {
		return false, nil
	}
	hasBuildID, err := f.hasBuildID()
	if err != nil {
		return false, err
	}
	if !hasBuildID {
		return true, nil
	}
	hasRealFiles, err := f.hasRealFiles()
	if err != nil {
		return false, err
	}
	return !hasRealFiles, nil
}

// ImportHash returns the import hash of an executable and the list of dynamic imports
// in the executable examined to generate the hash. For Windows PE format, the hash
// is calculated according to the algorithm described in the FireEye blog post
// https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html.
// For Linux, a similar construction is used with each imported symbol represented
// as library.symbol without trimming the extension from the library part, while
// Darwin imports are the list of symbols without a library prefix and is equivalent
// to the Anomali SymHash https://www.anomali.com/blog/symhash.
//
// Darwin:
//  ___error
//  __exit
//  _clock_gettime
//
// Linux:
//  libc.so.6.free
//  .agwrite
//  libc.so.6.puts
//
// Windows:
//  kernel32.writefile
//  kernel32.writeconsolew
//  kernel32.waitformultipleobjects
func (f *File) ImportHash() (hash []byte, imports []string, err error) {
	// Algorithm from https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
	//  - Resolving ordinals to function names when they appear (done by the debug/pe library)
	//  - Converting both DLL names and function names to all lowercase
	//  - Removing the file extensions from imported module names
	//  - Building and storing the lowercased string in an ordered list
	//  - Generating the MD5 hash of the ordered list
	//
	// The algorithm is generalised to non-Windows platforms as described in
	// the doc comment.

	imports, err = f.importedSymbols()
	if err != nil {
		return nil, nil, err
	}
	h := md5.New()
	if len(imports) == 0 {
		return h.Sum(nil), nil, nil
	}
	for i, imp := range imports {
		if i != 0 {
			_, _ = h.Write([]byte{','})
		}
		fmt.Fprint(h, imp)
	}
	return h.Sum(nil), imports, nil
}

// GoSymbolHash returns the symbol hash of a Go executable and the list of symbols
// in the executable examined to generate the hash. If stdlib is true, symbols
// from the Go standard library are included, otherwise only third-party symbols
// are considered.
//
// If the file at is an executable, but not a gc-compiled Go executable,
// ErrNotGoExecutable will be returned.
func (f *File) GoSymbolHash(stdlib bool) (hash []byte, imports []string, err error) {
	ok, err := f.isGoExecutable()
	if !ok || err != nil {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrNotGoExecutable
	}

	imports, err = f.goSymbols(stdlib)
	if err != nil {
		return nil, nil, err
	}
	h := md5.New()
	if len(imports) == 0 {
		return h.Sum(nil), nil, nil
	}
	for i, imp := range imports {
		if i != 0 {
			_, _ = h.Write([]byte{','})
		}
		fmt.Fprint(h, imp)
	}
	return h.Sum(nil), imports, nil
}

// Sections returns the names and sizes of object file sections in the order
// that they appear in file.
func (f *File) Sections() ([]Section, error) {
	return f.sectionStats()
}

// Section holds basic executable section information.
type Section struct {
	Name       string  // Name is the platform-specific name of the section.
	Size       uint64  // Size of the uncompressed size of the section.
	Entropy    float64 // Entropy is the Shannon entropy of the section data in bits.
	VarEntropy float64 // VarEntropy is an estimate of the variance of the section entropy.
}

// Stripped is a convenience wrapper around File.Stripped.
func Stripped(path string) (sneaky bool, err error) {
	f, err := Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()
	return f.Stripped()
}

// ImportHash is a convenience wrapper around File.ImportHash.
func ImportHash(path string) (hash []byte, imports []string, err error) {
	f, err := Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return f.ImportHash()
}

// GoSymbolHash is a convenience wrapper around File.GoSymbolHash.
func GoSymbolHash(path string, stdlib bool) (hash []byte, imports []string, err error) {
	f, err := Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	return f.GoSymbolHash(stdlib)
}

// Sections is a convenience wrapper around File.Sections.
func Sections(path string) ([]Section, error) {
	f, err := Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.Sections()
}

func isStdlib(s string, addr uint64, tab *gosym.Table) bool {
	if tab != nil {
		file, _, _ := tab.PCToLine(addr)
		if file == "??" {
			return false
		}
	}
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return true
	}
	dot := strings.IndexByte(s[:slash], '.')
	return dot < 0
}

// NameEntropy returns the entropy and entropy variance for the given import
// symbols names as a set.
func NameEntropy(symbols []string) (entropy, variance float64) {
	// Tally classes.
	var (
		counts [256]float64
		n      int
	)
	for _, data := range symbols {
		n += len(data)
		for _, b := range []byte(data) {
			counts[b]++
		}
	}

	return entropyVariance(&counts, n)
}

// streamEntropy returns the entropy and entropy variance for bytes in the
// provided io.Reader.
func streamEntropy(r io.Reader) (entropy, variance float64, err error) {
	// Tally classes.
	var (
		counts [256]float64
		n      int
		buf    [4096]byte
	)
	for {
		_n, err := r.Read(buf[:])
		n += _n
		for _, b := range buf[:_n] {
			counts[b]++
		}
		if err != nil {
			if err != io.EOF {
				return 0, 0, err
			}
			break
		}
	}

	entropy, variance = entropyVariance(&counts, n)
	return entropy, variance, nil
}

// entropyVariance returns the entropy and entropy variance for counts in
// counts for a sequence that is n long. See https://arxiv.org/pdf/1807.02603.pdf
// for details of the variance calculation.
func entropyVariance(counts *[256]float64, n int) (entropy, variance float64) {
	if n == 0 {
		return 0, 0
	}

	// H = -∑i=1..k((p_i)*log(p_i))
	// F² = ∑i=1..k((p_i)*log²(p_i)) - H²
	//
	// Variance in H is F²/N
	//
	// Calculated using the weighted incremental algorithm for
	// mean and variance estimates.
	// See https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Weighted_incremental_algorithm
	var pSum, pSum2 float64
	for _, cnt := range counts {
		if cnt == 0 {
			// Ignore zero counts.
			continue
		}
		p := cnt / float64(n)
		l2p := math.Log2(p)

		pSum += p
		pSum2 += p * p
		tmp := entropy
		entropy = tmp + (p/pSum)*(l2p-tmp)
		variance += p * (l2p - tmp) * (l2p - entropy)
	}
	variance /= float64(n)
	if entropy == 0 {
		// Don't negate zero.
		return 0, variance
	}
	return -entropy, variance
}
