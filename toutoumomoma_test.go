// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"os"
	"os/exec"
	"testing"
)

var scanTests = []struct {
	GOOS    string
	builder string
	want    bool
}{
	{
		GOOS:    "linux",
		builder: "go",
		want:    false,
	},
	{
		GOOS:    "linux",
		builder: "garble",
		want:    true,
	},
	{
		GOOS:    "darwin",
		builder: "go",
		want:    false,
	},
	{
		GOOS:    "darwin",
		builder: "garble",
		want:    true,
	},
	{
		GOOS:    "windows",
		builder: "go",
		want:    false,
	},
	{
		GOOS:    "windows",
		builder: "garble",
		want:    true,
	},
}

func TestScan(t *testing.T) {
	const (
		pkg    = "./testdata"
		target = "./testdata/executable"
	)

	for _, test := range scanTests {
		err := build(test.GOOS, test.builder, pkg, target)
		if err != nil {
			t.Errorf("failed to build test for GOOS=%s %s build testdata: %v", test.GOOS, test.builder, err)
			continue
		}
		got, err := Scan(target)
		if err != nil {
			t.Errorf("unexpected error scanning executable for GOOS=%s %s build testdata: %v",
				test.GOOS, test.builder, err)
			continue
		}
		if got != test.want {
			t.Errorf("unexpected result scanning executable for GOOS=%s %s build testdata: got:%t want:%t",
				test.GOOS, test.builder, got, test.want)
		}
	}
	os.Remove(target)
}

func build(goos, builder, path, target string) error {
	cmd := exec.Command(builder, "build", "-o", target, path)
	cmd.Env = append([]string{"GOOS=" + goos}, os.Environ()...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
