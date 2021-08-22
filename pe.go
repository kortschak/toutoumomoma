// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"debug/pe"
	"fmt"
	"os"
	"path"
	"strings"
)

type peFile struct {
	f       *os.File
	objFile *pe.File
}

func openPE(f *os.File) (*peFile, error) {
	objFile, err := pe.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &peFile{f: f, objFile: objFile}, nil
}

func (f *peFile) Close() error {
	return f.f.Close()
}

func (f *peFile) isGoExecutable() (ok bool, err error) {
	// TODO(kortschak): Investigate whether there is a better
	// heuristic or a definitive test for this case.
	rdata, err := f.objFile.Section(".rdata").Data()
	if err != nil {
		return false, err
	}
	return bytes.Contains(rdata, []byte("runtime.g")), nil
}

func (f *peFile) hasBuildID() (ok bool, err error) {
	for _, s := range f.objFile.Symbols {
		if s.Name == "go.buildid" {
			return true, nil
		}
	}
	return false, nil
}

func (f *peFile) importedSymbols() ([]string, error) {
	imports, err := f.objFile.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	for i, imp := range imports {
		imports[i], err = canonicaliseImport(imp)
		if err != nil {
			return nil, err
		}
	}
	return imports, nil
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

func (f *peFile) goSymbols(stdlib bool) ([]string, error) {
	imports := make([]string, 0, len(f.objFile.Symbols))
	for _, sym := range f.objFile.Symbols {
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
		if sym.SectionNumber < 0 || len(f.objFile.Sections) < int(sym.SectionNumber) {
			return nil, fmt.Errorf("invalid section number in symbol table")
		}

		const STYP_TEXT = 0x20 // https://wiki.osdev.org/COFF#Section_Header
		if f.objFile.Sections[sym.SectionNumber-1].Characteristics&STYP_TEXT == 0 {
			continue
		}

		if strings.HasPrefix(sym.Name, "type..") {
			continue
		}
		if !stdlib && isStdlib(sym.Name) {
			continue
		}
		imports = append(imports, sym.Name)
	}
	if len(imports) == 0 {
		imports = nil
	}
	return imports, nil
}
