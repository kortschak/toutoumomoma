// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Code derived from source in go/src/cmd/internal/objfile.

// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"debug/pe"
	"debug/plan9obj"
	"fmt"
)

// ELF PC to line preparation function.
func (f *elfFile) pcln() (textStart uint64, symtab, pclntab []byte, err error) {
	if sect := f.objFile.Section(".text"); sect != nil {
		textStart = sect.Addr
	}
	if sect := f.objFile.Section(".gosymtab"); sect != nil {
		if symtab, err = sect.Data(); err != nil {
			return 0, nil, nil, err
		}
	}
	if sect := f.objFile.Section(".gopclntab"); sect != nil {
		if pclntab, err = sect.Data(); err != nil {
			return 0, nil, nil, err
		}
	}
	return textStart, symtab, pclntab, nil
}

// Mach-O PC to line preparation function.
func (f *machoFile) pcln() (textStart uint64, symtab, pclntab []byte, err error) {
	if sect := f.objFile.Section("__text"); sect != nil {
		textStart = sect.Addr
	}
	if sect := f.objFile.Section("__gosymtab"); sect != nil {
		if symtab, err = sect.Data(); err != nil {
			return 0, nil, nil, err
		}
	}
	if sect := f.objFile.Section("__gopclntab"); sect != nil {
		if pclntab, err = sect.Data(); err != nil {
			return 0, nil, nil, err
		}
	}
	return textStart, symtab, pclntab, nil
}

// Plan9 PC to line preparation function.
func (f *plan9File) pcln() (textStart uint64, symtab, pclntab []byte, err error) {
	textStart = f.objFile.LoadAddress + f.objFile.HdrSize
	if pclntab, err = loadPlan9Table(f.objFile, "runtime.pclntab", "runtime.epclntab"); err != nil {
		return 0, nil, nil, err
	}
	if symtab, err = loadPlan9Table(f.objFile, "runtime.symtab", "runtime.esymtab"); err != nil {
		return 0, nil, nil, err
	}
	return textStart, symtab, pclntab, nil
}

func loadPlan9Table(f *plan9obj.File, sname, ename string) ([]byte, error) {
	ssym, err := findPlan9Symbol(f, sname)
	if err != nil {
		return nil, err
	}
	esym, err := findPlan9Symbol(f, ename)
	if err != nil {
		return nil, err
	}
	sect := f.Section("text")
	if sect == nil {
		return nil, err
	}
	data, err := sect.Data()
	if err != nil {
		return nil, err
	}
	textStart := f.LoadAddress + f.HdrSize
	return data[ssym.Value-textStart : esym.Value-textStart], nil
}

func findPlan9Symbol(f *plan9obj.File, name string) (*plan9obj.Sym, error) {
	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	for _, s := range syms {
		if s.Name != name {
			continue
		}
		return &s, nil
	}
	return nil, fmt.Errorf("no %s symbol found", name)
}

// PE PC to line preparation function.
func (f *peFile) pcln() (textStart uint64, symtab, pclntab []byte, err error) {
	var imageBase uint64
	switch oh := f.objFile.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		imageBase = uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		imageBase = oh.ImageBase
	default:
		return 0, nil, nil, fmt.Errorf("pe file format not recognized")
	}
	if sect := f.objFile.Section(".text"); sect != nil {
		textStart = imageBase + uint64(sect.VirtualAddress)
	}
	if pclntab, err = loadPETable(f.objFile, "runtime.pclntab", "runtime.epclntab"); err != nil {
		return 0, nil, nil, err
	}
	if symtab, err = loadPETable(f.objFile, "runtime.symtab", "runtime.esymtab"); err != nil {
		return 0, nil, nil, err
	}
	return textStart, symtab, pclntab, nil
}

func loadPETable(f *pe.File, sname, ename string) ([]byte, error) {
	ssym, err := findPESymbol(f, sname)
	if err != nil {
		return nil, err
	}
	esym, err := findPESymbol(f, ename)
	if err != nil {
		return nil, err
	}
	if ssym.SectionNumber != esym.SectionNumber {
		return nil, fmt.Errorf("%s and %s symbols must be in the same section", sname, ename)
	}
	sect := f.Sections[ssym.SectionNumber-1]
	data, err := sect.Data()
	if err != nil {
		return nil, err
	}
	return data[ssym.Value:esym.Value], nil
}

func findPESymbol(f *pe.File, name string) (*pe.Symbol, error) {
	for _, s := range f.Symbols {
		if s.Name != name {
			continue
		}
		if s.SectionNumber <= 0 {
			return nil, fmt.Errorf("symbol %s: invalid section number %d", name, s.SectionNumber)
		}
		if len(f.Sections) < int(s.SectionNumber) {
			return nil, fmt.Errorf("symbol %s: section number %d is larger than max %d", name, s.SectionNumber, len(f.Sections))
		}
		return s, nil
	}
	return nil, fmt.Errorf("no %s symbol found", name)
}
