// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"crypto/md5"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

// Stripped examines the file at the given path and returns whether it is
// likely to be a Go executable that has had its symbols stripped.
func Stripped(path string) (sneaky bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	var magic [4]byte
	_, err = f.ReadAt(magic[:], 0)
	if err != nil {
		if err != io.EOF {
			return false, nil
		}
	}
	switch {
	case bytes.Equal(magic[:], []byte("\x7FELF")):
		exe, err := elf.NewFile(f)
		if err != nil {
			return false, err
		}
		for _, section := range exe.Sections {
			switch section.Name {
			case ".gosymtab", ".gopclntab", ".go.buildinfo":
				sym, err := exe.Symbols()
				if err != nil {
					if err == elf.ErrNoSymbols {
						return true, nil
					}
					return true, err
				}
				for _, s := range sym {
					if s.Name == "go.buildid" {
						return false, nil
					}
				}
			}
		}
		return false, nil

	case bytes.Equal(magic[:3], []byte("\xFE\xED\xFA")) || bytes.Equal(magic[1:], []byte("\xFA\xED\xFE")):
		exe, err := macho.NewFile(f)
		if err != nil {
			return false, err
		}
		for _, section := range exe.Sections {
			switch section.Name {
			case "__gosymtab", "__gopclntab", "__go_buildinfo":
				for _, sym := range exe.Symtab.Syms {
					if sym.Name == "go.buildid" {
						return false, nil
					}
				}
				return true, nil
			}
		}
		return false, nil

	case bytes.Equal(magic[:2], []byte("MZ")):
		exe, err := pe.NewFile(f)
		if err != nil {
			return false, err
		}
		for _, sym := range exe.Symbols {
			if sym.Name == "go.buildid" {
				return false, nil
			}
		}
		rdata, err := exe.Section(".rdata").Data()
		if err != nil {
			return false, err
		}
		return bytes.Contains(rdata, []byte("runtime.g")), nil

	default:
		return false, nil
	}
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
//
func ImportHash(path string) (hash []byte, imports []string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	var magic [4]byte
	_, err = f.ReadAt(magic[:], 0)
	if err != nil {
		return nil, nil, err
	}
	switch {
	case bytes.Equal(magic[:], []byte("\x7FELF")):
		// Algorithm based on the PE imphash algorithm below.
		// This will likely not be useful for Go executables.

		exe, err := elf.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		imps, err := exe.ImportedSymbols()
		if err != nil && err != elf.ErrNoSymbols {
			return nil, nil, err
		}
		h := md5.New()
		if len(imps) == 0 {
			return h.Sum(nil), nil, nil
		}
		imports = make([]string, len(imps))
		for i, imp := range imps {
			imports[i] = strings.ToLower(imp.Library + "." + imp.Name)
			if i != 0 {
				_, _ = h.Write([]byte{','})
			}
			fmt.Fprint(h, imports[i])
		}
		return h.Sum(nil), imports, nil

	case bytes.Equal(magic[:3], []byte("\xFE\xED\xFA")) || bytes.Equal(magic[1:], []byte("\xFA\xED\xFE")):
		// Algorithm based on the PE imphash algorithm below.

		exe, err := macho.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		imports, err = exe.ImportedSymbols()
		if err != nil {
			return nil, nil, err
		}
		h := md5.New()
		for i, imp := range imports {
			if i != 0 {
				_, _ = h.Write([]byte{','})
			}
			fmt.Fprint(h, strings.ToLower(imp))
		}
		return h.Sum(nil), imports, nil

	case bytes.Equal(magic[:2], []byte("MZ")):
		// Algorithm from https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
		//  - Resolving ordinals to function names when they appear (done by the debug/pe library)
		//  - Converting both DLL names and function names to all lowercase
		//  - Removing the file extensions from imported module names
		//  - Building and storing the lowercased string in an ordered list
		//  - Generating the MD5 hash of the ordered list

		exe, err := pe.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		imports, err = exe.ImportedSymbols()
		if err != nil {
			return nil, nil, err
		}
		h := md5.New()
		for i, imp := range imports {
			imports[i], err = canonicaliseImport(imp)
			if err != nil {
				return nil, nil, err
			}
			if i != 0 {
				_, _ = h.Write([]byte{','})
			}
			fmt.Fprint(h, imports[i])
		}
		return h.Sum(nil), imports, nil

	default:
		return nil, nil, errors.New("unknown format")
	}
}

func canonicaliseImport(imp string) (string, error) {
	parts := strings.SplitN(strings.ToLower(imp), ":", 3)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid import symbol: %q", imp)
	}
	lib := strings.TrimSuffix(parts[1], path.Ext(parts[1]))
	fn := parts[0]
	return lib + "." + fn, nil
}
