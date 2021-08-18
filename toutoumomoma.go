// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"errors"
	"io"
	"os"
)

// Scan examines the file at the given path and returns whether it is likely
// to be a Go executable that has had its symbols stripped.
func Scan(path string) (sneaky bool, err error) {
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
				_, err = exe.Symbols()
				if err != nil {
					return true, nil
				}
			}
		}
		return false, nil

	case bytes.Equal(magic[:3], []byte("\xFE\xED\xFA")) || bytes.Equal(magic[1:], []byte("\xFA\xED\xFE")):
		exe, err := macho.NewFile(f)
		if err != nil {
			return false, err
		}
		var isGo bool
		for _, section := range exe.Sections {
			switch section.Name {
			case "__gosymtab", "__gopclntab", "__go_buildinfo":
				isGo = true
			}
		}
		if !isGo {
			return false, nil
		}
		for _, sym := range exe.Symtab.Syms {
			if sym.Name == "go.buildid" {
				return false, nil
			}
		}
		return true, nil

	case bytes.Equal(magic[:2], []byte("MZ")):
		return false, errors.New("not supported for windows")

	default:
		return false, nil
	}
}
