// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"debug/elf"
	"debug/gosym"
	"os"
	"strings"
)

type elfFile struct {
	f       *os.File
	objFile *elf.File
}

func openELF(f *os.File) (*elfFile, error) {
	objFile, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &elfFile{f: f, objFile: objFile}, nil
}

func (f *elfFile) Close() error {
	return f.f.Close()
}

func (f *elfFile) isGoExecutable() (ok bool, err error) {
	for _, section := range f.objFile.Sections {
		switch section.Name {
		case ".gosymtab", ".gopclntab", ".go.buildinfo":
			return true, nil
		}
	}
	return false, nil
}

func (f *elfFile) hasBuildID() (ok bool, err error) {
	sect := f.objFile.Section(".note.go.buildid")
	if sect == nil {
		return false, nil
	}
	_, err = sect.Data()
	return err == nil, err
}

func (f *elfFile) hasRealFiles() (ok bool, err error) {
	tab, err := f.pclnTable()
	if err != nil {
		return false, err
	}
	symbols, err := f.objFile.Symbols()
	if err != nil {
		if err == elf.ErrNoSymbols {
			return false, nil
		}
		return false, err
	}
	for _, sym := range symbols {
		if sym.Name != "main.main" {
			continue
		}
		file, _, _ := tab.PCToLine(sym.Value)
		if file == "??" {
			return false, nil
		}
	}
	return true, nil
}

func (f *elfFile) importedSymbols() ([]string, error) {
	imps, err := f.objFile.ImportedSymbols()
	if err != nil && err != elf.ErrNoSymbols {
		return nil, err
	}
	if len(imps) == 0 {
		return nil, nil
	}
	imports := make([]string, len(imps))
	for i, imp := range imps {
		imports[i] = strings.ToLower(imp.Library + "." + imp.Name)
	}
	return imports, nil
}

func (f *elfFile) goSymbols(stdlib bool) ([]string, error) {
	syms, err := f.objFile.Symbols()
	if err != nil {
		if err == elf.ErrNoSymbols {
			err = nil
		}
		return nil, err
	}
	if len(syms) == 0 {
		return nil, nil
	}
	tab, err := f.pclnTable()
	if err != nil {
		return nil, err
	}
	imports := make([]string, 0, len(syms))
	for _, sym := range syms {
		switch sym.Section {
		case elf.SHN_UNDEF, elf.SHN_COMMON:
			continue
		}
		if strings.HasPrefix(sym.Name, "type..") {
			continue
		}
		if !stdlib && isStdlib(sym.Name, sym.Value, tab) {
			continue
		}
		i := int(sym.Section)
		if i < 0 || i >= len(f.objFile.Sections) {
			continue
		}
		sect := f.objFile.Sections[i]
		if sect.Flags&(elf.SHF_ALLOC|elf.SHF_EXECINSTR) == elf.SHF_ALLOC|elf.SHF_EXECINSTR {
			imports = append(imports, sym.Name)
		}
	}
	if len(imports) == 0 {
		return nil, nil
	}
	return imports, nil
}

func (f *elfFile) pclnTable() (*gosym.Table, error) {
	textStart, symtab, pclntab, err := f.pcln()
	if err != nil {
		return nil, nil
	}
	return gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
}

func (f *elfFile) sectionStats() []Section {
	s := make([]Section, len(f.objFile.Sections))
	for i, sect := range f.objFile.Sections {
		s[i] = Section{Name: sect.Name, Size: sect.Size}
	}
	return s
}
