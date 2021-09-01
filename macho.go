// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"debug/gosym"
	"debug/macho"
	"os"
	"strings"
)

type machoFile struct {
	f       *os.File
	objFile *macho.File
}

func openMachO(f *os.File) (*machoFile, error) {
	objFile, err := macho.NewFile(f)
	if err != nil {
		return nil, err
	}
	return &machoFile{f: f, objFile: objFile}, nil
}

func (f *machoFile) Close() error {
	return f.f.Close()
}

func (f *machoFile) isGoExecutable() (ok bool, err error) {
	for _, section := range f.objFile.Sections {
		switch section.Name {
		case "__gosymtab", "__gopclntab", "__go_buildinfo":
			return true, nil
		}
	}
	return false, nil
}

func (f *machoFile) hasBuildID() (ok bool, err error) {
	sect := f.objFile.Section("__go_buildinfo")
	if sect == nil {
		return false, nil
	}
	_, err = sect.Data()
	return err == nil, err
}

func (f *machoFile) hasRealFiles() (ok bool, err error) {
	tab, err := f.pclnTable()
	if err != nil {
		return false, err
	}
	if len(f.objFile.Symtab.Syms) == 0 {
		return false, nil
	}
	for _, sym := range f.objFile.Symtab.Syms {
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

func (f *machoFile) importedSymbols() ([]string, error) {
	imports, err := f.objFile.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	for i, imp := range imports {
		imports[i] = strings.ToLower(imp)
	}
	return imports, nil
}

func (f *machoFile) goSymbols(stdlib bool) ([]string, error) {
	tab, err := f.pclnTable()
	if err != nil {
		return nil, err
	}
	imports := make([]string, 0, len(f.objFile.Symtab.Syms))
	for _, sym := range f.objFile.Symtab.Syms {
		if sym.Sect == 0 || int(sym.Sect) > len(f.objFile.Sections) {
			continue
		}
		sect := f.objFile.Sections[sym.Sect-1]
		if sect.Seg != "__TEXT" || sect.Name != "__text" {
			continue
		}
		if strings.HasPrefix(sym.Name, "type..") {
			continue
		}
		if !stdlib && isStdlib(sym.Name, sym.Value, tab) {
			continue
		}
		imports = append(imports, sym.Name)
	}
	if len(imports) == 0 {
		imports = nil
	}
	return imports, nil
}

func (f *machoFile) pclnTable() (*gosym.Table, error) {
	textStart, symtab, pclntab, err := f.pcln()
	if err != nil {
		return nil, nil
	}
	return gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
}

func (f *machoFile) sectionStats() []Section {
	s := make([]Section, len(f.objFile.Sections))
	for i, sect := range f.objFile.Sections {
		s[i] = Section{Name: sect.Name, Size: sect.Size}
	}
	return s
}
