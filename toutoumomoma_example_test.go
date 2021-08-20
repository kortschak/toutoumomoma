// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma_test

import (
	"fmt"
	"log"
	"os"

	"github.com/kortschak/toutoumomoma"
)

func Example() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <path>\n", os.Args[0])
		os.Exit(2)
	}
	sneaky, err := toutoumomoma.Stripped(os.Args[1])
	if err != nil && err != toutoumomoma.ErrUnknownFormat {
		log.Fatal(err)
	}
	if sneaky {
		fmt.Println("stripped")
	}
	h, imports, err := toutoumomoma.ImportHash(os.Args[1])
	if err != nil && err != toutoumomoma.ErrUnknownFormat {
		log.Fatal(err)
	}
	if len(imports) == 0 {
		return
	}
	fmt.Printf("imphash: %x\n", h)
	for _, i := range imports {
		fmt.Printf("\t%s\n", i)
	}
}
