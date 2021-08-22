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
		"go": {
			nil,
		},
		"garble": {
			nil,
			{"-literals"},
			{"-tiny"},
			{"-literals", "-tiny"},
		},
	}

	for _, goos := range []string{
		"linux",
		"darwin",
		"plan9",
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
					// Darwin does not strip symbols. See comment below.
					want := builder == "garble" && goos != "darwin"

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
					// The Windows want value obtained by running the get_imphash function from
					// https://github.com/erocarrera/pefile on the hello world executable.
					want := map[string]string{
						"darwin":  "d3ccf195b62a9279c3c19af1080497ec",
						"linux":   "d41d8cd98f00b204e9800998ecf8427e", // No dynamic imports.
						"plan9":   "d41d8cd98f00b204e9800998ecf8427e", // No dynamic imports.
						"windows": "c7269d59926fa4252270f407e4dab043",
					}

					// Obtained by inspection of debug/{elf,macho,pe,plan9obj} output.
					wantImports := map[string][]string{
						"darwin": {
							"___error",
							"__exit",
							"_clock_gettime",
							"_close",
							"_closedir",
							"_execve",
							"_fcntl",
							"_fstat64",
							"_getcwd",
							"_getpid",
							"_kevent",
							"_kill",
							"_kqueue",
							"_lseek",
							"_mach_absolute_time",
							"_mach_timebase_info",
							"_madvise",
							"_mmap",
							"_munmap",
							"_open",
							"_pipe",
							"_pthread_attr_getstacksize",
							"_pthread_attr_init",
							"_pthread_attr_setdetachstate",
							"_pthread_cond_init",
							"_pthread_cond_signal",
							"_pthread_cond_timedwait_relative_np",
							"_pthread_cond_wait",
							"_pthread_create",
							"_pthread_kill",
							"_pthread_mutex_init",
							"_pthread_mutex_lock",
							"_pthread_mutex_unlock",
							"_pthread_self",
							"_pthread_sigmask",
							"_raise",
							"_read",
							"_sigaction",
							"_sigaltstack",
							"_stat64",
							"_sysctl",
							"_usleep",
							"_write",
						},
						"linux": nil,
						"plan9": nil,
						"windows": {
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
							"kernel32.addvectoredexceptionhandler"},
					}

					got, gotImports, err := ImportHash(target)
					if err != nil {
						t.Errorf("unexpected error hashing executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}
					if fmt.Sprintf("%x", got) != want[goos] {
						t.Errorf("unexpected hash for executable for GOOS=%s %s: got:%x want:%s",
							goos, cmd, got, want[goos])
					}
					if !reflect.DeepEqual(gotImports, wantImports[goos]) {
						t.Errorf("unexpected imports for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotImports, wantImports[goos])
					}
				})

				t.Run(fmt.Sprintf("SymbolHash_%s_%s_%v", goos, builder, strings.Join(flags, "_")), func(t *testing.T) {
					// The expectation matrix is more complex than suggested by
					// this example. Darwin behaves differently to the three other
					// GOOS when the program is more complex, but this is enough
					// to test the system. Where Darwin behaves differently, it
					// retains symbols more than the others.
					//
					// An example of this:
					//  package main
					//
					//  import (
					//  	"fmt"
					//
					//  	"github.com/kortschak/ct"
					//  )
					//
					//  func main() {
					//  	blue := (ct.Fg(ct.BoldYellow)).Paint
					//  	fmt.Println(blue("hello, world"))
					//  }
					//
					// Which gives the following symbol list, in pseudo-Go
					// with the key being GOOS, builder, flags:
					//
					//  {"darwin", "*", "*"}: {
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  },
					//  {"linux", "go", ""}: {
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  },
					//  {"plan9", "go", ""}: {
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  },
					//  {"windows", "go", ""}: {
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  },
					//  {"!darwin", "garble", "*"}: nil,

					want := map[string]string{
						"go":     "b10a099a8babcdf0283916af8fa87240",
						"garble": "d41d8cd98f00b204e9800998ecf8427e",
					}

					// Obtained by inspection of go tool objdump output.
					wantImports := map[string][]string{
						"go": {
							"github.com/kortschak/toutoumomoma/testdata/b.Used",
							"github.com/kortschak/toutoumomoma/testdata/b.hash",
						},
						"garble": nil,
					}

					got, gotSymbols, err := GoSymbolHash(target, false)
					if err != nil {
						t.Errorf("unexpected error hashing executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}

					if fmt.Sprintf("%x", got) != want[builder] {
						t.Errorf("unexpected hash for executable for GOOS=%s %s: got:%x want:%s",
							goos, cmd, got, want[builder])
					}
					if !reflect.DeepEqual(gotSymbols, wantImports[builder]) {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotSymbols, wantImports[builder])
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
