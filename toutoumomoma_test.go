// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func TestToutoumomoma(t *testing.T) {
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

			for _, flags := range flagSets[builder] {
				cmd, err := build(goos, builder, pkg, target, flags)
				if err != nil {
					t.Errorf("failed to build test for GOOS=%s %s: %v",
						goos, cmd, err)
					continue
				}

				t.Run(fmt.Sprintf("Stripped_%s_%s_%v", goos, builder, strings.Join(flags, "_")), func(t *testing.T) {
					want := builder == "garble"

					got, err := Stripped(target)
					if err != nil {
						t.Errorf("unexpected error scanning executable for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}
					if got != want {
						t.Errorf("unexpected result scanning executable for GOOS=%s %s: got:%t want:%t",
							goos, cmd, got, want)
					}
				})

				t.Run(fmt.Sprintf("ImportHash_%s_%s_%v", goos, builder, strings.Join(flags, "_")), func(t *testing.T) {
					// Want value obtained by running the get_imphash function from
					// https://github.com/erocarrera/pefile on the hello world executable.
					want := "c7269d59926fa4252270f407e4dab043"

					// Obtained by inspection of debug/pe output.
					wantImports := []string{
						"kernel32.writefile",
						"kernel32.writeconsolew",
						"kernel32.waitformultipleobjects",
						"kernel32.waitforsingleobject",
						"kernel32.virtualquery",
						"kernel32.virtualfree",
						"kernel32.virtualalloc",
						"kernel32.switchtothread",
						"kernel32.suspendthread",
						"kernel32.sleep",
						"kernel32.setwaitabletimer",
						"kernel32.setunhandledexceptionfilter",
						"kernel32.setprocesspriorityboost",
						"kernel32.setevent",
						"kernel32.seterrormode",
						"kernel32.setconsolectrlhandler",
						"kernel32.resumethread",
						"kernel32.postqueuedcompletionstatus",
						"kernel32.loadlibrarya",
						"kernel32.loadlibraryw",
						"kernel32.setthreadcontext",
						"kernel32.getthreadcontext",
						"kernel32.getsysteminfo",
						"kernel32.getsystemdirectorya",
						"kernel32.getstdhandle",
						"kernel32.getqueuedcompletionstatusex",
						"kernel32.getprocessaffinitymask",
						"kernel32.getprocaddress",
						"kernel32.getenvironmentstringsw",
						"kernel32.getconsolemode",
						"kernel32.freeenvironmentstringsw",
						"kernel32.exitprocess",
						"kernel32.duplicatehandle",
						"kernel32.createwaitabletimerexw",
						"kernel32.createthread",
						"kernel32.createiocompletionport",
						"kernel32.createfilea",
						"kernel32.createeventa",
						"kernel32.closehandle",
						"kernel32.addvectoredexceptionhandler",
					}

					got, gotImports, err := ImportHash(target)
					if err != nil {
						if goos == "windows" {
							t.Errorf("unexpected error hashing executable imports for GOOS=%s %s: %v",
								goos, cmd, err)
						}
						return
					}
					if goos != "windows" && err == nil {
						t.Errorf("expected error hashing executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
					}
					if fmt.Sprintf("%x", got) != want {
						t.Errorf("unexpected hash for executable for %s: got:%x want:%s",
							cmd, got, want)
					}
					if !reflect.DeepEqual(gotImports, wantImports) {
						t.Errorf("unexpected imports for %s: got:%x want:%s",
							cmd, gotImports, wantImports)
					}
				})
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
