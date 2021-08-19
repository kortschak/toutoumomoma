// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"os"
	"os/exec"
	"testing"
)

func TestScan(t *testing.T) {
	const (
		pkg    = "./testdata"
		target = "./testdata/executable"
	)

	flagSets := map[string][][]string{
		"go": nil,
		"garble": [][]string{
			nil,
			{"-literals"},
			{"-tiny"},
			{"-literals", "-tiny"},
		},
	}

	for _, goos := range []string{
		"linux",
		"darwin",
		"windows",
	} {
		for _, builder := range []string{
			"go",
			"garble",
		} {
			want := builder == "garble"

			for _, flags := range flagSets[builder] {
				cmd, err := build(goos, builder, pkg, target, flags)
				if err != nil {
					t.Errorf("failed to build test for GOOS=%s %s: %v",
						goos, cmd, err)
					continue
				}
				got, err := Scan(target)
				if err != nil {
					t.Errorf("unexpected error scanning executable for GOOS=%s %s: %v",
						goos, cmd, err)
					continue
				}
				if got != want {
					t.Errorf("unexpected result scanning executable for GOOS=%s %s: got:%t want:%t",
						goos, cmd, got, want)
				}
			}
		}
	}
	os.Remove(target)
}

func build(goos, builder, path, target string, flags []string) (*exec.Cmd, error) {
	cmd := exec.Command(builder, append(flags[:len(flags):len(flags)], "build", "-o", target, path)...)
	cmd.Env = append([]string{"GOOS=" + goos}, os.Environ()...)
	cmd.Stderr = os.Stderr
	return cmd, cmd.Run()
}
