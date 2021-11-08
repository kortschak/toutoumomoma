// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"fmt"
	"math"
	"math/rand"
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
					// https://github.com/erocarrera/pefile and https://github.com/threatstream/symhash/
					// on the hello world executable.
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
					// but fully enumerated, format as below:
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
						{"*", "go", "*"}:           "b10a099a8babcdf0283916af8fa87240",
						{"!darwin", "garble", "*"}: "d41d8cd98f00b204e9800998ecf8427e", // No symbols.

						// Garbled darwin hashes are not stable over Go versions.
						// So they are omitted.
					}

					// Obtained by inspection of go tool objdump output.
					wantImports := map[[3]string][]string{
						{"*", "go", "*"}: {
							"github.com/kortschak/toutoumomoma/testdata/b.Used",
							"github.com/kortschak/toutoumomoma/testdata/b.hash",
						},
						{"!darwin", "garble", "*"}: nil,

						// Garbled darwin hashes are not stable over Go versions,
						// but are retained for demonstration
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

					const tolEnt = 1
					wantEntropy := map[[3]string]float64{
						{"*", "go", "*"}:                        3.89,
						{"!darwin", "garble", "*"}:              0,
						{"darwin", "garble", ""}:                4.00,
						{"darwin", "garble", "-literals"}:       4.21,
						{"darwin", "garble", "-tiny"}:           4.58,
						{"darwin", "garble", "-literals -tiny"}: 4.59,
					}
					const tolVar = 0.01
					wantVariance := map[[3]string]float64{
						{"*", "go", "*"}:                        0.007,
						{"!darwin", "garble", "*"}:              0,
						{"darwin", "garble", ""}:                0.012,
						{"darwin", "garble", "-literals"}:       0.022,
						{"darwin", "garble", "-tiny"}:           0.017,
						{"darwin", "garble", "-literals -tiny"}: 0.006,
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

					if (goos != "darwin" || builder != "garble") && fmt.Sprintf("%x", got) != want[buildFor] {
						t.Errorf("unexpected hash for executable for GOOS=%s %s: got:%x want:%s",
							goos, cmd, got, want[buildFor])
					}

					if !reflect.DeepEqual(gotSymbols, wantImports[buildFor]) && !hasMain(gotSymbols) {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotSymbols, wantImports[buildFor])
					}

					gotEntropy, gotVariance := NameEntropy(gotSymbols)
					if math.Abs(gotEntropy-wantEntropy[buildFor]) > tolEnt {
						t.Errorf("unexpected symbol name entropy for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotEntropy, wantEntropy[buildFor])
					}
					if math.Abs(gotVariance-wantVariance[buildFor]) > tolEnt {
						t.Errorf("unexpected symbol name entropy for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotVariance, wantVariance[buildFor])
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
					const tol = 0.5
					want := map[[2]string][]Section{
						{"linux", "go"}: {
							{Name: "", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: ".text", Size: 0x7fff6, Entropy: 6.1720, VarEntropy: 1.0671e-05},
							{Name: ".rodata", Size: 0x35920, Entropy: 4.3510, VarEntropy: 5.6869e-05},
							{Name: ".shstrtab", Size: 0x17a, Entropy: 4.3325, VarEntropy: 0.0018},
							{Name: ".typelink", Size: 0x4f0, Entropy: 3.7700, VarEntropy: 0.0083},
							{Name: ".itablink", Size: 0x60, Entropy: 2.0450, VarEntropy: 0.0469},
							{Name: ".gosymtab", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: ".gopclntab", Size: 0x5a1e8, Entropy: 5.4742, VarEntropy: 2.4991e-05},
							{Name: ".go.buildinfo", Size: 0x20, Entropy: 3.5608, VarEntropy: 0.0716},
							{Name: ".noptrdata", Size: 0x10720, Entropy: 5.6082, VarEntropy: 0.0001},
							{Name: ".data", Size: 0x7810, Entropy: 1.6046, VarEntropy: 0.0003},
							{Name: ".bss", Size: 0x2ef48, Entropy: 7.9938, VarEntropy: 8.9795e-08},
							{Name: ".noptrbss", Size: 0x5360, Entropy: 7.9765, VarEntropy: 3.1677e-06},
							{Name: ".zdebug_abbrev", Size: 0x119, Entropy: 7.1866, VarEntropy: 0.0023},
							{Name: ".zdebug_line", Size: 0x1b8ac, Entropy: 7.9913, VarEntropy: 2.1037e-07},
							{Name: ".zdebug_frame", Size: 0x5526, Entropy: 7.9224, VarEntropy: 1.0161e-05},
							{Name: ".debug_gdb_scripts", Size: 0x2c, Entropy: 4.2655, VarEntropy: 0.0173},
							{Name: ".zdebug_info", Size: 0x31a5e, Entropy: 7.9955, VarEntropy: 6.3020e-08},
							{Name: ".zdebug_loc", Size: 0x198ca, Entropy: 7.9878, VarEntropy: 3.4217e-07},
							{Name: ".zdebug_ranges", Size: 0x8fac, Entropy: 7.7849, VarEntropy: 1.6544e-05},
							{Name: ".note.go.buildid", Size: 0x64, Entropy: 5.3359, VarEntropy: 0.0108},
							{Name: ".symtab", Size: 0xc5e8, Entropy: 3.2065, VarEntropy: 0.0002},
							{Name: ".strtab", Size: 0xb288, Entropy: 4.8111, VarEntropy: 4.9840e-05},
						},
						{"linux", "garble"}: {
							{Name: "", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: ".text", Size: 0x7fff6, Entropy: 6.1725, VarEntropy: 1.0665e-05},
							{Name: ".rodata", Size: 0x35880, Entropy: 4.3456, VarEntropy: 5.6899e-05},
							{Name: ".shstrtab", Size: 0x94, Entropy: 4.2789, VarEntropy: 0.0060},
							{Name: ".typelink", Size: 0x4f0, Entropy: 3.7700, VarEntropy: 0.0083},
							{Name: ".itablink", Size: 0x60, Entropy: 2.1640, VarEntropy: 0.0497},
							{Name: ".gosymtab", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: ".gopclntab", Size: 0x593e8, Entropy: 5.4475, VarEntropy: 2.5723e-05},
							{Name: ".go.buildinfo", Size: 0x20, Entropy: 3.4681, VarEntropy: 0.0831},
							{Name: ".noptrdata", Size: 0x10720, Entropy: 5.6078, VarEntropy: 0.0001},
							{Name: ".data", Size: 0x77f0, Entropy: 1.5832, VarEntropy: 0.0003},
							{Name: ".bss", Size: 0x2ef48, Entropy: 0.0, VarEntropy: 0.0},
							{Name: ".noptrbss", Size: 0x5360, Entropy: 0.0, VarEntropy: 0.0},
						},
						{"plan9", "go"}: {
							{Name: "text", Size: 0x1108a8, Entropy: 5.8811, VarEntropy: 7.1246e-06},
							{Name: "data", Size: 0x17000, Entropy: 4.6411, VarEntropy: 0.0001},
							{Name: "syms", Size: 0xe9ac, Entropy: 5.0949, VarEntropy: 8.5734e-05},
							{Name: "spsz", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "pcsz", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
						},
						{"plan9", "garble"}: {
							{Name: "text", Size: 0x10fa88, Entropy: 5.8773, VarEntropy: 7.1795e-06},
							{Name: "data", Size: 0x17000, Entropy: 4.6409, VarEntropy: 0.0001},
							{Name: "syms", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "spsz", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "pcsz", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
						},
						{"darwin", "go"}: {
							{Name: "__text", Size: 0x8be56, Entropy: 6.1663, VarEntropy: 9.8645e-06},
							{Name: "__symbol_stub1", Size: 0x102, Entropy: 3.5781, VarEntropy: 0.0155},
							{Name: "__rodata", Size: 0x38b2f, Entropy: 4.3747, VarEntropy: 5.2720e-05},
							{Name: "__typelink", Size: 0x550, Entropy: 3.6495, VarEntropy: 0.0081},
							{Name: "__itablink", Size: 0x78, Entropy: 2.6320, VarEntropy: 0.0342},
							{Name: "__gosymtab", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "__gopclntab", Size: 0x61060, Entropy: 5.4661, VarEntropy: 2.2468e-05},
							{Name: "__go_buildinfo", Size: 0x20, Entropy: 3.7959, VarEntropy: 0.0527},
							{Name: "__nl_symbol_ptr", Size: 0x158, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "__noptrdata", Size: 0x10780, Entropy: 5.5995, VarEntropy: 0.0001},
							{Name: "__data", Size: 0x7470, Entropy: 1.7430, VarEntropy: 0.0003},
							{Name: "__bss", Size: 0x2f068, Entropy: 6.1405, VarEntropy: 3.0289e-05},
							{Name: "__noptrbss", Size: 0x51c0, Entropy: 5.6567, VarEntropy: 0.0003},
							{Name: "__zdebug_abbrev", Size: 0x117, Entropy: 7.1660, VarEntropy: 0.0022},
							{Name: "__zdebug_line", Size: 0x1d5a0, Entropy: 7.9905, VarEntropy: 2.1397e-07},
							{Name: "__zdebug_frame", Size: 0x5b76, Entropy: 7.9273, VarEntropy: 8.8502e-06},
							{Name: "__debug_gdb_scri", Size: 0x2c, Entropy: 4.2655, VarEntropy: 0.0173},
							{Name: "__zdebug_info", Size: 0x33afe, Entropy: 7.9954, VarEntropy: 6.2728e-08},
							{Name: "__zdebug_loc", Size: 0x1a5c7, Entropy: 7.9845, VarEntropy: 4.2414e-07},
							{Name: "__zdebug_ranges", Size: 0x8387, Entropy: 7.8919, VarEntropy: 8.7597e-06},
						},
						{"darwin", "garble"}: {
							{Name: "__text", Size: 0x8bdd6, Entropy: 6.1665, VarEntropy: 9.8671e-06},
							{Name: "__symbol_stub1", Size: 0x102, Entropy: 3.4893, VarEntropy: 0.0158},
							{Name: "__rodata", Size: 0x38a8e, Entropy: 4.3682, VarEntropy: 5.2636e-05},
							{Name: "__typelink", Size: 0x550, Entropy: 3.6495, VarEntropy: 0.0081},
							{Name: "__itablink", Size: 0x78, Entropy: 2.6682, VarEntropy: 0.0356},
							{Name: "__gosymtab", Size: 0x0, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "__gopclntab", Size: 0x60140, Entropy: 5.4453, VarEntropy: 2.2954e-05},
							{Name: "__go_buildinfo", Size: 0x20, Entropy: 3.8584, VarEntropy: 0.0554},
							{Name: "__nl_symbol_ptr", Size: 0x158, Entropy: 0.0, VarEntropy: 0.0},
							{Name: "__noptrdata", Size: 0x10780, Entropy: 5.5995, VarEntropy: 0.0001},
							{Name: "__data", Size: 0x7470, Entropy: 1.7619, VarEntropy: 0.0003},
							{Name: "__bss", Size: 0x2f088, Entropy: 6.1313, VarEntropy: 3.0383e-05},
							{Name: "__noptrbss", Size: 0x51c0, Entropy: 5.5645, VarEntropy: 0.0003},
						},
						{"windows", "go"}: {
							{Name: ".text", Size: 0x8e400, Entropy: 6.1760, VarEntropy: 9.7432e-06},
							{Name: ".rdata", Size: 0x9e600, Entropy: 5.1365, VarEntropy: 1.6483e-05},
							{Name: ".data", Size: 0x17a00, Entropy: 4.6012, VarEntropy: 0.0001},
							{Name: ".zdebug_abbrev", Size: 0x200, Entropy: 4.8292, VarEntropy: 0.0245},
							{Name: ".zdebug_line", Size: 0x1cc00, Entropy: 7.9931, VarEntropy: 1.6213e-07},
							{Name: ".zdebug_frame", Size: 0x5800, Entropy: 7.9199, VarEntropy: 1.0050e-05},
							{Name: ".debug_gdb_scripts", Size: 0x200, Entropy: 0.7691, VarEntropy: 0.0089},
							{Name: ".zdebug_info", Size: 0x32a00, Entropy: 7.9963, VarEntropy: 5.0900e-08},
							{Name: ".zdebug_loc", Size: 0x1ba00, Entropy: 7.9898, VarEntropy: 2.6332e-07},
							{Name: ".zdebug_ranges", Size: 0x9600, Entropy: 7.7783, VarEntropy: 1.6865e-05},
							{Name: ".idata", Size: 0x600, Entropy: 3.6148, VarEntropy: 0.0051},
							{Name: ".reloc", Size: 0x6a00, Entropy: 5.4441, VarEntropy: 2.4045e-05},
							{Name: ".symtab", Size: 0x17800, Entropy: 5.1330, VarEntropy: 6.7475e-05},
						},
						{"windows", "garble"}: {
							{Name: ".text", Size: 0x8e400, Entropy: 6.1740, VarEntropy: 9.7411e-06},
							{Name: ".rdata", Size: 0x9d600, Entropy: 5.1323, VarEntropy: 1.6707e-05},
							{Name: ".data", Size: 0x17a00, Entropy: 4.6054, VarEntropy: 0.0001},
							{Name: ".idata", Size: 0x600, Entropy: 3.5545, VarEntropy: 0.0051},
							{Name: ".reloc", Size: 0x6a00, Entropy: 5.4427, VarEntropy: 2.3421e-05},
							{Name: ".symtab", Size: 0x200, Entropy: 0.0203, VarEntropy: 0.0003},
						},
					}

					got, err := Sections(target)
					if err != nil {
						t.Errorf("unexpected error examining executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}

					buildFor := [2]string{goos, builder}

					if wrong, ok := similarSections(got, want[buildFor], tol); !ok {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, got, want[buildFor])
						if wrong >= 0 {
							t.Logf("%d: %+v != %v", wrong, got[wrong], want[buildFor][wrong])
						}
					}
				})

			}
		}
	}
	os.Remove(target)
}

// hasMain returns whether the symbols in sym include main.main.
func hasMain(sym []string) bool {
	for _, s := range sym {
		if strings.HasPrefix(s, "main.main") {
			return true
		}
	}
	return false
}

// similarSections returns whether a and b a similar. For this comparison
// similarity is defined as have the same set of sections and corresponding
// sections having the same zero-size status.
func similarSections(a, b []Section, tol float64) (wrong int, ok bool) {
	if len(a) != len(b) {
		return -1, false
	}
	for i, s := range a {
		if s.Name != b[i].Name {
			return i, false
		}
		if (s.Size == 0) != (b[i].Size == 0) {
			return i, false
		}
		if math.Abs(s.Entropy-b[i].Entropy) > tol {
			return i, false
		}
		if math.Abs(s.VarEntropy-b[i].VarEntropy) > tol/100 {
			return i, false
		}
	}
	return 0, true
}

func build(goos, builder, path, target string, flags []string) (*exec.Cmd, error) {
	cmd := exec.Command(builder, append(flags[:len(flags):len(flags)], "build", "-o", target, path)...)
	cmd.Env = append([]string{"GOOS=" + goos}, os.Environ()...)
	cmd.Stderr = os.Stderr
	return cmd, cmd.Run()
}

func TestEntropyVariance(t *testing.T) {
	const (
		etol = 1e-15
		vtol = 1e-12
	)

	for _, l := range []int{32, 64, 128, 256} {
		for i := 0; i < 10; i++ {
			var (
				n [256]float64
				N int
			)
			for j := range n[:l] {
				r := rand.Intn(1e5 * l / 256)
				N += r
				n[j] = float64(r)
			}

			e, v := entropyVariance(&n, N)
			eNaive, vNaive := entropyVarianceNaive(&n, N)

			if r := relDiff(e, eNaive); r > etol {
				t.Errorf("entropy outside tolerance: l=%d N=%d e=%g e_naive=%g relerror=%g",
					l, N, e, eNaive, r)
			}
			if r := relDiff(v, vNaive); r > vtol {
				t.Errorf("variance outside tolerance: l=%d N=%d v=%g v_naive=%g relerror=%g",
					l, N, v, vNaive, r)
			}
		}
	}
}

func relDiff(a, b float64) float64 {
	return math.Abs(a-b) / math.Max(a, b)
}

// entropyVarianceNaive is a reference implementation of the fluctuation
// calculation in https://arxiv.org/pdf/1807.02603.pdf.
func entropyVarianceNaive(counts *[256]float64, n int) (entropy, variance float64) {
	if n == 0 {
		return 0, 0
	}

	// H = -∑i=1..k((p_i)*log(p_i))
	// F² = ∑i=1..k((p_i)*log²(p_i)) - H²
	//
	// Variance in H is F²/N
	for _, cnt := range counts {
		if cnt == 0 {
			// Ignore zero counts.
			continue
		}
		p := cnt / float64(n)
		l2p := math.Log2(p)
		entropy += p * l2p
		variance += p * l2p * l2p
	}
	variance -= entropy * entropy
	variance /= float64(n)
	if entropy == 0 {
		// Don't negate zero.
		return 0, variance
	}
	return -entropy, variance
}
