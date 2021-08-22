// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma_test

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kortschak/toutoumomoma"
)

func Example() {
	stdlib := flag.Bool("stdlib", false, "include standard library in Go symbol hash")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [-stdlib] <path>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) != 1 {
		flag.Usage()
		os.Exit(2)
	}
	path := flag.Args()[0]

	f, err := toutoumomoma.Open(path)
	if err != nil {
		if err == toutoumomoma.ErrUnknownFormat {
			os.Exit(0)
		}
		log.Fatal(err)
	}
	defer f.Close()

	sneaky, err := f.Stripped()
	if err != nil {
		log.Fatal(err)
	}
	if sneaky {
		fmt.Println("stripped")
	}

	h, imports, err := f.ImportHash()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("imphash: %x\n", h)
	if len(imports) != 0 {
		for _, i := range imports {
			fmt.Printf("\t%s\n", i)
		}
	}

	h, symbols, err := f.GoSymbolHash(*stdlib)
	if err != nil {
		if err == toutoumomoma.ErrNotGoExecutable {
			os.Exit(0)
		}
		log.Fatal(err)
	}
	fmt.Printf("symhash: %x\n", h)
	if len(symbols) != 0 {
		for _, i := range symbols {
			fmt.Printf("\t%s\n", i)
		}
	}
}
