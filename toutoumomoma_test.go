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

				t.Run(fmt.Sprintf("GoSymbolHash_%s_%s_%v", goos, builder, strings.Join(flags, "_")), func(t *testing.T) {
					// The expectation matrix is more complex than suggested by
					// this example. Darwin behaves differently to the three other
					// GOOS when the program is more complex, but this is enough
					// to test the system.
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
					// Which gives the following symbol list, in the same,
					// but fully enumerate, format as below:
					//
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
					//  {"darwin", "go", ""}: {
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  },
					//  {"darwin", "garble", ""}: {
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"main.main",
					//  },
					//  {"darwin", "garble", "-literals"}: {
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"main.main",
					//  },
					//  {"darwin", "garble", "-tiny"}: {
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"main.main",
					//  },
					//  {"darwin", "garble", "-literals -tiny"}: {
					//  	"github.com/kortschak/ct.(*text).Format",
					//  	"github.com/kortschak/ct.Mode.Paint-fm",
					//  	"github.com/kortschak/ct.Mode.set",
					//  	"github.com/kortschak/ct.doesString",
					//  	"github.com/kortschak/ct.text.Format",
					//  	"main.main",
					//  	"main.main.func1",
					//  },

					want := map[[3]string]string{
						{"*", "go", "*"}:                        "b10a099a8babcdf0283916af8fa87240",
						{"!darwin", "garble", "*"}:              "d41d8cd98f00b204e9800998ecf8427e", // No symbols.
						{"darwin", "garble", ""}:                "81ad8e9d7528ef595afebe3124f64709",
						{"darwin", "garble", "-literals"}:       "155c951d9fb1782cc334a1508b038fb9",
						{"darwin", "garble", "-tiny"}:           "602ae57f76a164b6e0e2dcbdf0bdf5bd",
						{"darwin", "garble", "-literals -tiny"}: "ab1b6fe467e1ccfd22ab50aca6afb439",
					}

					// Obtained by inspection of go tool objdump output.
					wantImports := map[[3]string][]string{
						{"*", "go", "*"}: {
							"github.com/kortschak/toutoumomoma/testdata/b.Used",
							"github.com/kortschak/toutoumomoma/testdata/b.hash",
						},
						{"!darwin", "garble", "*"}: nil,
						{"darwin", "garble", ""}: {
							"bkPYSmYe.OQNnrAXY",
							"main.main",
						},
						{"darwin", "garble", "-literals"}: {
							"GF2YkJwI.EKiCITp0",
							"main.main",
						},
						{"darwin", "garble", "-tiny"}: {
							"TOwBHPzl.XF2iNaVd",
							"TOwBHPzl.bzWzX77_",
							"main.main",
						},
						{"darwin", "garble", "-literals -tiny"}: {
							"Ag1I9czh.Be2apzTk",
							"Ag1I9czh.Be2apzTk.func1",
							"Ag1I9czh.eP3dBev5",
							"Ag1I9czh.eP3dBev5.func1",
							"main.main",
							"main.main.func1",
						},
					}

					got, gotSymbols, err := GoSymbolHash(target, false)
					if err != nil {
						t.Errorf("unexpected error hashing executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}

					buildFor := [3]string{goos, builder, strings.Join(flags, " ")}
					switch {
					case builder == "go":
						buildFor[0] = "*"
						buildFor[2] = "*"
					case goos != "darwin":
						buildFor[0] = "!darwin"
						buildFor[2] = "*"
					}

					if fmt.Sprintf("%x", got) != want[buildFor] {
						t.Errorf("unexpected hash for executable for GOOS=%s %s: got:%x want:%s",
							goos, cmd, got, want[buildFor])
					}
					if !reflect.DeepEqual(gotSymbols, wantImports[buildFor]) {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotSymbols, wantImports[buildFor])
					}
				})

				// Only test with and without garble.
				if len(flags) != 0 {
					continue
				}
				t.Run(fmt.Sprintf("SectionStats_%s_%s", goos, builder), func(t *testing.T) {
					// Included purely for regression testing. ELF values confirmed
					// by inspection of readelf output. We may expect these values
					// to change with different builder versions.
					want := map[[2]string][]Section{
						{"linux", "go"}: {
							{Name: "", Size: 0x0},
							{Name: ".text", Size: 0x7ff76},
							{Name: ".rodata", Size: 0x35900},
							{Name: ".shstrtab", Size: 0x17a},
							{Name: ".typelink", Size: 0x4f0},
							{Name: ".itablink", Size: 0x60},
							{Name: ".gosymtab", Size: 0x0},
							{Name: ".gopclntab", Size: 0x5a1e8},
							{Name: ".go.buildinfo", Size: 0x20},
							{Name: ".noptrdata", Size: 0x10720},
							{Name: ".data", Size: 0x7810},
							{Name: ".bss", Size: 0x2ef48},
							{Name: ".noptrbss", Size: 0x5360},
							{Name: ".zdebug_abbrev", Size: 0x119},
							{Name: ".zdebug_line", Size: 0x1b8af},
							{Name: ".zdebug_frame", Size: 0x5513},
							{Name: ".debug_gdb_scripts", Size: 0x2c},
							{Name: ".zdebug_info", Size: 0x31a5f},
							{Name: ".zdebug_loc", Size: 0x1988b},
							{Name: ".zdebug_ranges", Size: 0x8f8a},
							{Name: ".note.go.buildid", Size: 0x64},
							{Name: ".symtab", Size: 0xc5e8},
							{Name: ".strtab", Size: 0xb288},
						},
						{"linux", "garble"}: {
							{Name: "", Size: 0x0},
							{Name: ".text", Size: 0x7ff76},
							{Name: ".rodata", Size: 0x35880},
							{Name: ".shstrtab", Size: 0x94},
							{Name: ".typelink", Size: 0x4f0},
							{Name: ".itablink", Size: 0x60},
							{Name: ".gosymtab", Size: 0x0},
							{Name: ".gopclntab", Size: 0x593e8},
							{Name: ".go.buildinfo", Size: 0x20},
							{Name: ".noptrdata", Size: 0x10720},
							{Name: ".data", Size: 0x77f0},
							{Name: ".bss", Size: 0x2ef48},
							{Name: ".noptrbss", Size: 0x5360},
						},
						{"plan9", "go"}: {
							{Name: "text", Size: 0x110848},
							{Name: "data", Size: 0x17000},
							{Name: "syms", Size: 0xe9ac},
							{Name: "spsz", Size: 0x0},
							{Name: "pcsz", Size: 0x0},
						},
						{"plan9", "garble"}: {
							{Name: "text", Size: 0x10fa28},
							{Name: "data", Size: 0x17000},
							{Name: "syms", Size: 0x0},
							{Name: "spsz", Size: 0x0},
							{Name: "pcsz", Size: 0x0},
						},
						{"darwin", "go"}: {
							{Name: "__text", Size: 0x8bcf6},
							{Name: "__symbol_stub1", Size: 0x102},
							{Name: "__rodata", Size: 0x38aed},
							{Name: "__typelink", Size: 0x550},
							{Name: "__itablink", Size: 0x78},
							{Name: "__gosymtab", Size: 0x0},
							{Name: "__gopclntab", Size: 0x60fc8},
							{Name: "__go_buildinfo", Size: 0x20},
							{Name: "__nl_symbol_ptr", Size: 0x158},
							{Name: "__noptrdata", Size: 0x10780},
							{Name: "__data", Size: 0x7470},
							{Name: "__bss", Size: 0x2f068},
							{Name: "__noptrbss", Size: 0x51c0},
							{Name: "__zdebug_abbrev", Size: 0x117},
							{Name: "__zdebug_line", Size: 0x1d592},
							{Name: "__zdebug_frame", Size: 0x5b69},
							{Name: "__debug_gdb_scri", Size: 0x2c},
							{Name: "__zdebug_info", Size: 0x33a0e},
							{Name: "__zdebug_loc", Size: 0x1a503},
							{Name: "__zdebug_ranges", Size: 0x837b},
						},
						{"darwin", "garble"}: {
							{Name: "__text", Size: 0x8bc76},
							{Name: "__symbol_stub1", Size: 0x102},
							{Name: "__rodata", Size: 0x38a6d},
							{Name: "__typelink", Size: 0x550},
							{Name: "__itablink", Size: 0x78},
							{Name: "__gosymtab", Size: 0x0},
							{Name: "__gopclntab", Size: 0x60088},
							{Name: "__go_buildinfo", Size: 0x20},
							{Name: "__nl_symbol_ptr", Size: 0x158},
							{Name: "__noptrdata", Size: 0x10780},
							{Name: "__data", Size: 0x7470},
							{Name: "__bss", Size: 0x2f088},
							{Name: "__noptrbss", Size: 0x51c0},
						},
						{"windows", "go"}: {
							{Name: ".text", Size: 0x8e400},
							{Name: ".rdata", Size: 0x9e400},
							{Name: ".data", Size: 0x17a00},
							{Name: ".zdebug_abbrev", Size: 0x200},
							{Name: ".zdebug_line", Size: 0x1cc00},
							{Name: ".zdebug_frame", Size: 0x5800},
							{Name: ".debug_gdb_scripts", Size: 0x200},
							{Name: ".zdebug_info", Size: 0x32a00},
							{Name: ".zdebug_loc", Size: 0x1ba00},
							{Name: ".zdebug_ranges", Size: 0x9400},
							{Name: ".idata", Size: 0x600},
							{Name: ".reloc", Size: 0x6a00},
							{Name: ".symtab", Size: 0x17800},
						},
						{"windows", "garble"}: {
							{Name: ".text", Size: 0x8e400},
							{Name: ".rdata", Size: 0x9d600},
							{Name: ".data", Size: 0x17a00},
							{Name: ".idata", Size: 0x600},
							{Name: ".reloc", Size: 0x6a00},
							{Name: ".symtab", Size: 0x200},
						},
					}

					got, err := Sections(target)
					if err != nil {
						t.Errorf("unexpected error examining executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}

					buildFor := [2]string{goos, builder}

					if !similarSections(got, want[buildFor]) {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, got, want[buildFor])
					}
				})

			}
		}
	}
	os.Remove(target)
}

// similarSections returns whether a and b a similar. For this comparison
// similarity is defined as have the same set of sections and corresponding
// sections having the same zero-size status.
func similarSections(a, b []Section) bool {
	if len(a) != len(b) {
		return false
	}
	for i, s := range a {
		if s.Name != b[i].Name {
			return false
		}
		if (s.Size == 0) != (b[i].Size == 0) {
			return false
		}
	}
	return true
}

func build(goos, builder, path, target string, flags []string) (*exec.Cmd, error) {
	cmd := exec.Command(builder, append(flags[:len(flags):len(flags)], "build", "-o", target, path)...)
	cmd.Env = append([]string{"GOOS=" + goos}, os.Environ()...)
	cmd.Stderr = os.Stderr
	return cmd, cmd.Run()
}
