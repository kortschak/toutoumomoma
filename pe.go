// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"debug/gosym"
	"debug/pe"
	"fmt"
	"io"
	"path"
	"strings"
)

type peFile struct {
	r       io.ReaderAt
	objFile *pe.File
}

func openPE(r io.ReaderAt) (*peFile, error) {
	objFile, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &peFile{r: r, objFile: objFile}, nil
}

func (f *peFile) Close() error {
	f.objFile = nil
	if c, ok := f.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (f *peFile) isGoExecutable() (ok bool, err error) {
	// TODO(kortschak): Investigate whether there is a better
	// heuristic or a definitive test for this case.
	sect := f.objFile.Section(".rdata")
	if sect == nil {
		return false, nil
	}
	rdata, err := sect.Data()
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

func (f *peFile) hasRealFiles() (ok bool, err error) {
	tab, err := f.pclnTable()
	if err != nil {
		return false, err
	}
	if len(f.objFile.Symbols) == 0 {
		return false, nil
	}
	for _, sym := range f.objFile.Symbols {
		if sym.Name != "main.main" {
			continue
		}
		file, _, _ := tab.PCToLine(uint64(sym.Value))
		if file == "??" {
			return false, nil
		}
	}
	return true, nil
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
	tab, err := f.pclnTable()
	if err != nil {
		return nil, err
	}
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
		if !stdlib && isStdlib(sym.Name, uint64(sym.Value), tab) {
			continue
		}
		imports = append(imports, sym.Name)
	}
	if len(imports) == 0 {
		imports = nil
	}
	return imports, nil
}

func (f *peFile) pclnTable() (*gosym.Table, error) {
	textStart, symtab, pclntab, err := f.pcln()
	if err != nil {
		return nil, nil
	}
	return gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
}

func (f *peFile) sectionStats() ([]Section, error) {
	s := make([]Section, len(f.objFile.Sections))
	for i, sect := range f.objFile.Sections {
		h, sigma, err := streamEntropy(sect.Open())
		if err != nil {
			return nil, err
		}
		s[i] = Section{
			Name:       sect.Name,
			Size:       uint64(sect.Size),
			Entropy:    h,
			VarEntropy: sigma,
			Flags:      sect.Characteristics,
		}
	}
	return s, nil
}
