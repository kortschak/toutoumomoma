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
	io.Closer
}

// Open opens the file at at the provided path.
//
// If the file at path is not an ELF, Mach-O, plan9obj or PE format
// executable, ImportHash will return ErrUnknownFormat. Files without
// execute permissions may be opened.
func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var magic [4]byte
	_, err = f.ReadAt(magic[:], 0)
	if err != nil {
		if err != io.EOF {
			return nil, nil
		}
	}
	switch {
	case bytes.Equal(magic[:], []byte("\x7FELF")):
		exe, err := openELF(f)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	case bytes.Equal(magic[:3], []byte("\xfe\xed\xfa")),
		bytes.Equal(magic[1:], []byte("\xfa\xed\xfe")):
		exe, err := openMachO(f)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	case bytes.Equal(magic[:2], []byte("MZ")):
		exe, err := openPE(f)
		if err != nil {
			return nil, err
		}
		return &File{exe}, nil

	case bytes.Equal(magic[:], []byte("\x00\x00\x01\xeb")),
		bytes.Equal(magic[:], []byte("\x00\x00\x8a\x97")),
		bytes.Equal(magic[:], []byte("\x00\x00\x06G")):
		exe, err := openPlan9(f)
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

// Close closes the file.
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
// Darwin imports are the list of symbols without a library prefix.
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
