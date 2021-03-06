// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"debug/gosym"
	"debug/plan9obj"
	"io"
	"strings"
)

type plan9File struct {
	r       io.ReaderAt
	objFile *plan9obj.File
}

func openPlan9(r io.ReaderAt) (*plan9File, error) {
	objFile, err := plan9obj.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &plan9File{r: r, objFile: objFile}, nil
}

func (f *plan9File) Close() error {
	f.objFile = nil
	if c, ok := f.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (f *plan9File) isGoExecutable() (ok bool, err error) {
	// TODO(kortschak): Investigate whether there is a better
	// heuristic or a definitive test for this case.
	sect := f.objFile.Section("text")
	if sect == nil {
		return false, nil
	}
	text, err := sect.Data()
	if err != nil {
		return false, err
	}
	return bytes.Contains(text, []byte("runtime.g")), nil
}

func (f *plan9File) hasBuildID() (ok bool, err error) {
	if f.objFile.Section("syms") == nil {
		return false, nil
	}
	syms, err := f.objFile.Symbols()
	if err != nil {
		return false, err
	}
	for _, s := range syms {
		if s.Name == "go.buildid" {
			return true, nil
		}
	}
	return false, nil
}

func (f *plan9File) hasRealFiles() (ok bool, err error) {
	tab, err := f.pclnTable()
	if err != nil {
		return false, err
	}
	symbols, err := f.objFile.Symbols()
	if err != nil {
		// Sadly, plan9obj doesn't export the no symbol error value.
		if f.objFile.Section("syms") == nil {
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

func (f *plan9File) importedSymbols() ([]string, error) {
	return nil, nil
}

func (f *plan9File) goSymbols(stdlib bool) ([]string, error) {
	syms, err := f.objFile.Symbols()
	if err != nil {
		if f.objFile.Section("syms") == nil {
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
		if sym.Type != 'T' {
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
		return nil, nil
	}
	return imports, nil
}

func (f *plan9File) pclnTable() (*gosym.Table, error) {
	textStart, symtab, pclntab, err := f.pcln()
	if err != nil {
		return nil, nil
	}
	return gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
}

func (f *plan9File) sectionStats() ([]Section, error) {
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
		}
	}
	return s, nil
}
