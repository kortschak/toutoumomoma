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
	"debug/plan9obj"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
)

var (
	// ErrUnknownFormat is returned for files that are not recognized.
	ErrUnknownFormat = errors.New("unknown format")

	// ErrNotGoExecutable indicates a file was not a Go executable.
	ErrNotGoExecutable = errors.New("not a Go executable")
)

// Stripped examines the file at the given path and returns whether it is
// likely to be a Go executable that has had its symbols stripped.
// If the file at path is not an ELF, Mach-O, plan9obj or PE format
// executable, Stripped will return ErrUnknownFormat.
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

	case bytes.Equal(magic[:3], []byte("\xfe\xed\xfa")), bytes.Equal(magic[1:], []byte("\xfa\xed\xfe")):
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

	case bytes.Equal(magic[:], []byte("\x00\x00\x01\xeb")),
		bytes.Equal(magic[:], []byte("\x00\x00\x8a\x97")),
		bytes.Equal(magic[:], []byte("\x00\x00\x06G")):
		exe, err := plan9obj.NewFile(f)
		if err != nil {
			return false, err
		}
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
		text, err := exe.Section("text").Data()
		if err != nil {
			return false, err
		}
		return bytes.Contains(text, []byte("runtime.g")), nil

	default:
		return false, ErrUnknownFormat
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
// Plan9 does not support dynamic linking so ImportHash will always return values
// for the empty set of imports, md5("") and nil, for the plan9obj format.
//
// If the file at path is not an ELF, Mach-O, plan9obj or PE format
// executable, ImportHash will return ErrUnknownFormat.
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

	case bytes.Equal(magic[:3], []byte("\xfe\xed\xfa")), bytes.Equal(magic[1:], []byte("\xfa\xed\xfe")):
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

	case bytes.Equal(magic[:], []byte("\x00\x00\x01\xeb")),
		bytes.Equal(magic[:], []byte("\x00\x00\x8a\x97")),
		bytes.Equal(magic[:], []byte("\x00\x00\x06G")):
		// Algorithm based on the PE imphash algorithm above
		// except that plan9 does not have dynamically linked
		// libraries, so don't even bother trying.

		return []byte("\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e"), nil, nil

	default:
		return nil, nil, ErrUnknownFormat
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

// GoSymbolHash returns the symbol hash of a Go executable and the list of symbols
// in the executable examined to generate the hash. If stdlib is true, symbols
// from the Go standard library are included, otherwise only third-party symbols
// are considered.
//
// If the file at path is not an ELF, Mach-O, plan9obj or PE format executable,
// GoSymbolHash will return ErrUnknownFormat. If it an executable, but not a
// gc-compiled Go executable, ErrNotGoExecutable will be returned.
func GoSymbolHash(path string, stdlib bool) (hash []byte, imports []string, err error) {
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
		exe, err := elf.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		var isGo bool
	elfLoop:
		for _, section := range exe.Sections {
			switch section.Name {
			case ".gosymtab", ".gopclntab", ".go.buildinfo":
				isGo = true
				break elfLoop
			}
		}
		if !isGo {
			return nil, nil, ErrNotGoExecutable
		}

		syms, err := exe.Symbols()
		if err != nil && err != elf.ErrNoSymbols {
			return nil, nil, err
		}
		h := md5.New()
		if len(syms) == 0 {
			return h.Sum(nil), nil, nil
		}
		imports = make([]string, 0, len(syms))
		for _, sym := range syms {
			switch sym.Section {
			case elf.SHN_UNDEF, elf.SHN_COMMON:
				continue
			}
			if strings.HasPrefix(sym.Name, "type..") {
				continue
			}
			if !stdlib && isStdlib(sym.Name) {
				continue
			}
			i := int(sym.Section)
			if i < 0 || i >= len(exe.Sections) {
				continue
			}
			sect := exe.Sections[i]
			if sect.Flags&(elf.SHF_ALLOC|elf.SHF_EXECINSTR) == elf.SHF_ALLOC|elf.SHF_EXECINSTR {
				if len(imports) != 0 {
					_, _ = h.Write([]byte{','})
				}
				imports = append(imports, sym.Name)
				fmt.Fprint(h, sym.Name)
			}
		}
		if len(imports) == 0 {
			imports = nil
		}
		return h.Sum(nil), imports, nil

	case bytes.Equal(magic[:3], []byte("\xfe\xed\xfa")), bytes.Equal(magic[1:], []byte("\xfa\xed\xfe")):
		exe, err := macho.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		var isGo bool
	machOLoop:
		for _, section := range exe.Sections {
			switch section.Name {
			case "__gosymtab", "__gopclntab", "__go_buildinfo":
				isGo = true
				break machOLoop
			}
		}
		if !isGo {
			return nil, nil, ErrNotGoExecutable
		}

		h := md5.New()
		imports = make([]string, 0, len(exe.Symtab.Syms))
		for _, sym := range exe.Symtab.Syms {
			if sym.Sect == 0 || int(sym.Sect) > len(exe.Sections) {
				continue
			}
			sect := exe.Sections[sym.Sect-1]
			if sect.Seg != "__TEXT" || sect.Name != "__text" {
				continue
			}
			if strings.HasPrefix(sym.Name, "type..") {
				continue
			}
			if !stdlib && isStdlib(sym.Name) {
				continue
			}
			if len(imports) != 0 {
				_, _ = h.Write([]byte{','})
			}
			imports = append(imports, sym.Name)
			fmt.Fprint(h, sym.Name)
		}
		if len(imports) == 0 {
			imports = nil
		}
		return h.Sum(nil), imports, nil

	case bytes.Equal(magic[:2], []byte("MZ")):
		exe, err := pe.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		rdata, err := exe.Section(".rdata").Data()
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Contains(rdata, []byte("runtime.g")) {
			return nil, nil, ErrNotGoExecutable
		}

		h := md5.New()
		imports = make([]string, 0, len(exe.Symbols))
		for _, sym := range exe.Symbols {
			// https://wiki.osdev.org/COFF#Symbol_Table
			const (
				N_UNDEF = 0
				N_ABS   = -1
				N_DEBUG = -2
			)
			switch sym.SectionNumber {
			case N_UNDEF, N_ABS, N_DEBUG:
				continue
			}
			if sym.SectionNumber < 0 || len(exe.Sections) < int(sym.SectionNumber) {
				return nil, nil, fmt.Errorf("invalid section number in symbol table")
			}

			const STYP_TEXT = 0x20 // https://wiki.osdev.org/COFF#Section_Header
			if exe.Sections[sym.SectionNumber-1].Characteristics&STYP_TEXT == 0 {
				continue
			}

			if strings.HasPrefix(sym.Name, "type..") {
				continue
			}
			if !stdlib && isStdlib(sym.Name) {
				continue
			}
			if len(imports) != 0 {
				_, _ = h.Write([]byte{','})
			}
			imports = append(imports, sym.Name)
			fmt.Fprint(h, sym.Name)
		}
		if len(imports) == 0 {
			imports = nil
		}
		return h.Sum(nil), imports, nil

	case bytes.Equal(magic[:], []byte("\x00\x00\x01\xeb")),
		bytes.Equal(magic[:], []byte("\x00\x00\x8a\x97")),
		bytes.Equal(magic[:], []byte("\x00\x00\x06G")):

		exe, err := plan9obj.NewFile(f)
		if err != nil {
			return nil, nil, err
		}
		text, err := exe.Section("text").Data()
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Contains(text, []byte("runtime.g")) {
			return nil, nil, ErrNotGoExecutable
		}

		syms, err := exe.Symbols()
		if err != nil && err != elf.ErrNoSymbols {
			return nil, nil, err
		}
		h := md5.New()
		if len(syms) == 0 {
			return h.Sum(nil), nil, nil
		}
		imports = make([]string, 0, len(syms))
		for _, sym := range syms {
			if sym.Type != 'T' {
				continue
			}
			if strings.HasPrefix(sym.Name, "type..") {
				continue
			}
			if !stdlib && isStdlib(sym.Name) {
				continue
			}
			if len(imports) != 0 {
				_, _ = h.Write([]byte{','})
			}
			imports = append(imports, sym.Name)
			fmt.Fprint(h, sym.Name)
		}
		if len(imports) == 0 {
			imports = nil
		}
		return h.Sum(nil), imports, nil

	default:
		return nil, nil, ErrUnknownFormat
	}
}

func isStdlib(s string) bool {
	slash := strings.IndexByte(s, '/')
	if slash < 0 {
		return true
	}
	dot := strings.IndexByte(s[:slash], '.')
	return dot < 0
}
