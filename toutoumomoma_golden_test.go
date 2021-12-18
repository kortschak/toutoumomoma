// Code generate by go test -generate github.com/kortschak/toutoumomoma. DO NOT EDIT.

// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

// goldenValues is the list of known golden values keyed on Go and Garble version
// at the first level and test details in the second level.
var goldenValues = map[string]map[test]interface{}{
	"go1.17.5:v0.4.0": map[test]interface{}{
		test{
			name:    "ImportHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "-literals",
		}: importHashTestResults{
			hash: "d3ccf195b62a9279c3c19af1080497ec",
			imports: []string{
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
		},
		test{
			name:    "ImportHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "-literals",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "GoSymbolHash",
			goos:    "windows",
			builder: "go",
			flags:   "",
		}: symbolHashTestResults{
			hash: "b10a099a8babcdf0283916af8fa87240",
			imports: []string{
				"github.com/kortschak/toutoumomoma/testdata/b.Used",
				"github.com/kortschak/toutoumomoma/testdata/b.hash",
			},
			entropy:  3.8913328650565453,
			variance: 0.0072997875567589006,
		},
		test{
			name:    "SectionStats",
			goos:    "windows",
			builder: "garble",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       ".text",
					Size:       0x8e400,
					Entropy:    6.174219578291682,
					VarEntropy: 9.747369960039817e-06,
				},
				Section{
					Name:       ".rdata",
					Size:       0x9d600,
					Entropy:    5.131207218044359,
					VarEntropy: 1.671073994258933e-05,
				},
				Section{
					Name:       ".data",
					Size:       0x17a00,
					Entropy:    4.605289268139611,
					VarEntropy: 0.0001513937129465353,
				},
				Section{
					Name:       ".idata",
					Size:       0x600,
					Entropy:    3.5545243710280534,
					VarEntropy: 0.0051654859306460325,
				},
				Section{
					Name:       ".reloc",
					Size:       0x6a00,
					Entropy:    5.4381901305203595,
					VarEntropy: 2.3255531494436373e-05,
				},
				Section{
					Name:       ".symtab",
					Size:       0x200,
					Entropy:    0.020393135236084953,
					VarEntropy: 0.0003081937203618641,
				},
			},
		},
		test{
			name:    "SectionStats",
			goos:    "darwin",
			builder: "go",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       "__text",
					Size:       0x8beb6,
					Entropy:    6.166788335680352,
					VarEntropy: 9.863806074376723e-06,
				},
				Section{
					Name:       "__symbol_stub1",
					Size:       0x102,
					Entropy:    3.4893399598381714,
					VarEntropy: 0.01585074784028974,
				},
				Section{
					Name:       "__rodata",
					Size:       0x38b2f,
					Entropy:    4.380076990934671,
					VarEntropy: 5.275236905659203e-05,
				},
				Section{
					Name:       "__typelink",
					Size:       0x550,
					Entropy:    3.6495169670279215,
					VarEntropy: 0.008187743833172039,
				},
				Section{
					Name:       "__itablink",
					Size:       0x78,
					Entropy:    2.6631709458911685,
					VarEntropy: 0.0347247167012339,
				},
				Section{
					Name:       "__gosymtab",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "__gopclntab",
					Size:       0x610c0,
					Entropy:    5.47013059388382,
					VarEntropy: 2.2520357634932778e-05,
				},
				Section{
					Name:       "__go_buildinfo",
					Size:       0x20,
					Entropy:    3.7959585933443494,
					VarEntropy: 0.052778240182421145,
				},
				Section{
					Name:       "__nl_symbol_ptr",
					Size:       0x158,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "__noptrdata",
					Size:       0x10780,
					Entropy:    5.599890017368,
					VarEntropy: 0.00016906838984816983,
				},
				Section{
					Name:       "__data",
					Size:       0x7470,
					Entropy:    1.7437119429494201,
					VarEntropy: 0.00036301843349099635,
				},
				Section{
					Name:       "__bss",
					Size:       0x2f068,
					Entropy:    6.139704184531683,
					VarEntropy: 3.0284753345571777e-05,
				},
				Section{
					Name:       "__noptrbss",
					Size:       0x51c0,
					Entropy:    5.653664356107006,
					VarEntropy: 0.00037981931601000385,
				},
				Section{
					Name:       "__zdebug_abbrev",
					Size:       0x117,
					Entropy:    7.166065824433167,
					VarEntropy: 0.0022405772861620005,
				},
				Section{
					Name:       "__zdebug_line",
					Size:       0x1d5c5,
					Entropy:    7.991127843423397,
					VarEntropy: 2.0212417105952686e-07,
				},
				Section{
					Name:       "__zdebug_frame",
					Size:       0x5b90,
					Entropy:    7.931221335818104,
					VarEntropy: 8.399860586863567e-06,
				},
				Section{
					Name:       "__debug_gdb_scri",
					Size:       0x2c,
					Entropy:    4.265583322887733,
					VarEntropy: 0.01731684668465522,
				},
				Section{
					Name:       "__zdebug_info",
					Size:       0x33b80,
					Entropy:    7.996167745278472,
					VarEntropy: 5.167859750132946e-08,
				},
				Section{
					Name:       "__zdebug_loc",
					Size:       0x1a6ba,
					Entropy:    7.984926337700013,
					VarEntropy: 4.1118774999903916e-07,
				},
				Section{
					Name:       "__zdebug_ranges",
					Size:       0x838f,
					Entropy:    7.891479517426951,
					VarEntropy: 8.821148933818937e-06,
				},
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "",
		}: symbolHashTestResults{
			hash: "c66aedc8ad4d994151824d9ae04f31d6",
			imports: []string{
				"Xhfmd6vu.ERkO_8S8",
				"main.main",
			},
			entropy:  4.132944044980958,
			variance: 0.013554709424015496,
		},
		test{
			name:    "ImportHash",
			goos:    "linux",
			builder: "garble",
			flags:   "-literals-tiny",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "ImportHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "-tiny",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "ImportHash",
			goos:    "windows",
			builder: "garble",
			flags:   "-literals",
		}: importHashTestResults{
			hash: "c7269d59926fa4252270f407e4dab043",
			imports: []string{
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
			},
		},
		test{
			name:    "ImportHash",
			goos:    "linux",
			builder: "garble",
			flags:   "-literals",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "ImportHash",
			goos:    "linux",
			builder: "garble",
			flags:   "-tiny",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "GoSymbolHash",
			goos:    "plan9",
			builder: "go",
			flags:   "",
		}: symbolHashTestResults{
			hash: "b10a099a8babcdf0283916af8fa87240",
			imports: []string{
				"github.com/kortschak/toutoumomoma/testdata/b.Used",
				"github.com/kortschak/toutoumomoma/testdata/b.hash",
			},
			entropy:  3.8913328650565453,
			variance: 0.0072997875567589006,
		},
		test{
			name:    "ImportHash",
			goos:    "windows",
			builder: "go",
			flags:   "",
		}: importHashTestResults{
			hash: "c7269d59926fa4252270f407e4dab043",
			imports: []string{
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
			},
		},
		test{
			name:    "ImportHash",
			goos:    "windows",
			builder: "garble",
			flags:   "",
		}: importHashTestResults{
			hash: "c7269d59926fa4252270f407e4dab043",
			imports: []string{
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
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "windows",
			builder: "garble",
			flags:   "",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "SectionStats",
			goos:    "linux",
			builder: "garble",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       "",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       ".text",
					Size:       0x7fff6,
					Entropy:    6.1726348037427226,
					VarEntropy: 1.0665784772777106e-05,
				},
				Section{
					Name:       ".rodata",
					Size:       0x35880,
					Entropy:    4.345693523795199,
					VarEntropy: 5.689945809821882e-05,
				},
				Section{
					Name:       ".shstrtab",
					Size:       0x94,
					Entropy:    4.278922006970282,
					VarEntropy: 0.006074968357746798,
				},
				Section{
					Name:       ".typelink",
					Size:       0x4f0,
					Entropy:    3.7700952245237347,
					VarEntropy: 0.008305293779624193,
				},
				Section{
					Name:       ".itablink",
					Size:       0x60,
					Entropy:    2.1011498751545608,
					VarEntropy: 0.046760554373954454,
				},
				Section{
					Name:       ".gosymtab",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       ".gopclntab",
					Size:       0x593e8,
					Entropy:    5.447476636422382,
					VarEntropy: 2.5723218153134535e-05,
				},
				Section{
					Name:       ".go.buildinfo",
					Size:       0x20,
					Entropy:    3.4681390622295662,
					VarEntropy: 0.08313705052107564,
				},
				Section{
					Name:       ".noptrdata",
					Size:       0x10720,
					Entropy:    5.6079008723320936,
					VarEntropy: 0.0001693604060627171,
				},
				Section{
					Name:       ".data",
					Size:       0x77f0,
					Entropy:    1.582695899677633,
					VarEntropy: 0.0003591461339251088,
				},
				Section{
					Name:       ".bss",
					Size:       0x2ef48,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       ".noptrbss",
					Size:       0x5360,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "-literals",
		}: symbolHashTestResults{
			hash: "4975af8e574a8a7ab7b67a5498bafb44",
			imports: []string{
				"H66IYw3R.EG258N6M",
				"main.main",
			},
			entropy:  4.132944044980959,
			variance: 0.0135547094240155,
		},
		test{
			name:    "ImportHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "-literals-tiny",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "GoSymbolHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "-literals",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "GoSymbolHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "-tiny",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "ImportHash",
			goos:    "darwin",
			builder: "go",
			flags:   "",
		}: importHashTestResults{
			hash: "d3ccf195b62a9279c3c19af1080497ec",
			imports: []string{
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
		},
		test{
			name:    "GoSymbolHash",
			goos:    "darwin",
			builder: "go",
			flags:   "",
		}: symbolHashTestResults{
			hash: "b10a099a8babcdf0283916af8fa87240",
			imports: []string{
				"github.com/kortschak/toutoumomoma/testdata/b.Used",
				"github.com/kortschak/toutoumomoma/testdata/b.hash",
			},
			entropy:  3.8913328650565453,
			variance: 0.0072997875567589006,
		},
		test{
			name:    "ImportHash",
			goos:    "plan9",
			builder: "go",
			flags:   "",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "ImportHash",
			goos:    "windows",
			builder: "garble",
			flags:   "-literals-tiny",
		}: importHashTestResults{
			hash: "c7269d59926fa4252270f407e4dab043",
			imports: []string{
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
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "linux",
			builder: "go",
			flags:   "",
		}: symbolHashTestResults{
			hash: "b10a099a8babcdf0283916af8fa87240",
			imports: []string{
				"github.com/kortschak/toutoumomoma/testdata/b.Used",
				"github.com/kortschak/toutoumomoma/testdata/b.hash",
			},
			entropy:  3.8913328650565453,
			variance: 0.0072997875567589006,
		},
		test{
			name:    "ImportHash",
			goos:    "linux",
			builder: "garble",
			flags:   "",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "ImportHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "",
		}: importHashTestResults{
			hash: "d3ccf195b62a9279c3c19af1080497ec",
			imports: []string{
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
		},
		test{
			name:    "GoSymbolHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "-tiny",
		}: symbolHashTestResults{
			hash: "62b2f3abcd0f24edbcbd4d7e20d60d3b",
			imports: []string{
				"JwTaDs6G.Lkix37cj",
				"JwTaDs6G.f6mJljuG",
				"main.main",
			},
			entropy:  4.297675800911846,
			variance: 0.009977420320126346,
		},
		test{
			name:    "ImportHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "GoSymbolHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "ImportHash",
			goos:    "windows",
			builder: "garble",
			flags:   "-tiny",
		}: importHashTestResults{
			hash: "c7269d59926fa4252270f407e4dab043",
			imports: []string{
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
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "windows",
			builder: "garble",
			flags:   "-tiny",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "GoSymbolHash",
			goos:    "linux",
			builder: "garble",
			flags:   "",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "GoSymbolHash",
			goos:    "linux",
			builder: "garble",
			flags:   "-tiny",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "GoSymbolHash",
			goos:    "linux",
			builder: "garble",
			flags:   "-literals-tiny",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "SectionStats",
			goos:    "darwin",
			builder: "garble",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       "__text",
					Size:       0x8be36,
					Entropy:    6.167347591819188,
					VarEntropy: 9.867355524334404e-06,
				},
				Section{
					Name:       "__symbol_stub1",
					Size:       0x102,
					Entropy:    3.6276890098831465,
					VarEntropy: 0.015016544046307864,
				},
				Section{
					Name:       "__rodata",
					Size:       0x38a8f,
					Entropy:    4.376612275317795,
					VarEntropy: 5.280387075386776e-05,
				},
				Section{
					Name:       "__typelink",
					Size:       0x550,
					Entropy:    3.6495169670279215,
					VarEntropy: 0.008187743833172039,
				},
				Section{
					Name:       "__itablink",
					Size:       0x78,
					Entropy:    2.6067374825531435,
					VarEntropy: 0.034873377046304554,
				},
				Section{
					Name:       "__gosymtab",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "__gopclntab",
					Size:       0x601a0,
					Entropy:    5.450014394459792,
					VarEntropy: 2.300325694260958e-05,
				},
				Section{
					Name:       "__go_buildinfo",
					Size:       0x20,
					Entropy:    3.8584585933443494,
					VarEntropy: 0.05540633161466978,
				},
				Section{
					Name:       "__nl_symbol_ptr",
					Size:       0x158,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "__noptrdata",
					Size:       0x10780,
					Entropy:    5.599381100755206,
					VarEntropy: 0.00016907674543298053,
				},
				Section{
					Name:       "__data",
					Size:       0x7470,
					Entropy:    1.7609293377327442,
					VarEntropy: 0.0003625007880729216,
				},
				Section{
					Name:       "__bss",
					Size:       0x2f088,
					Entropy:    6.1311721379240485,
					VarEntropy: 3.0386837114991553e-05,
				},
				Section{
					Name:       "__noptrbss",
					Size:       0x51c0,
					Entropy:    5.565361401346228,
					VarEntropy: 0.0003931745779535265,
				},
			},
		},
		test{
			name:    "ImportHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "-tiny",
		}: importHashTestResults{
			hash: "d3ccf195b62a9279c3c19af1080497ec",
			imports: []string{
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
		},
		test{
			name:    "GoSymbolHash",
			goos:    "plan9",
			builder: "garble",
			flags:   "-literals-tiny",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "GoSymbolHash",
			goos:    "windows",
			builder: "garble",
			flags:   "-literals-tiny",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "ImportHash",
			goos:    "linux",
			builder: "go",
			flags:   "",
		}: importHashTestResults{
			hash:    "d41d8cd98f00b204e9800998ecf8427e",
			imports: []string(nil),
		},
		test{
			name:    "SectionStats",
			goos:    "linux",
			builder: "go",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       "",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       ".text",
					Size:       0x7fff6,
					Entropy:    6.1720093737546,
					VarEntropy: 1.0671493890547944e-05,
				},
				Section{
					Name:       ".rodata",
					Size:       0x35920,
					Entropy:    4.351078638675726,
					VarEntropy: 5.6869549960717754e-05,
				},
				Section{
					Name:       ".shstrtab",
					Size:       0x17a,
					Entropy:    4.332514286812163,
					VarEntropy: 0.0018720932548837838,
				},
				Section{
					Name:       ".typelink",
					Size:       0x4f0,
					Entropy:    3.7700952245237347,
					VarEntropy: 0.008305293779624193,
				},
				Section{
					Name:       ".itablink",
					Size:       0x60,
					Entropy:    2.045054107939454,
					VarEntropy: 0.04696294988334262,
				},
				Section{
					Name:       ".gosymtab",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       ".gopclntab",
					Size:       0x5a1e8,
					Entropy:    5.474218747550726,
					VarEntropy: 2.499111219906954e-05,
				},
				Section{
					Name:       ".go.buildinfo",
					Size:       0x20,
					Entropy:    3.5608203810934285,
					VarEntropy: 0.07164523745026193,
				},
				Section{
					Name:       ".noptrdata",
					Size:       0x10720,
					Entropy:    5.60821346272867,
					VarEntropy: 0.0001693709947955346,
				},
				Section{
					Name:       ".data",
					Size:       0x7810,
					Entropy:    1.6046467490248555,
					VarEntropy: 0.0003631319373646502,
				},
				Section{
					Name:       ".bss",
					Size:       0x2ef48,
					Entropy:    7.9939814167373955,
					VarEntropy: 8.816451131074686e-08,
				},
				Section{
					Name:       ".noptrbss",
					Size:       0x5360,
					Entropy:    7.97808162806558,
					VarEntropy: 2.9092720639125194e-06,
				},
				Section{
					Name:       ".zdebug_abbrev",
					Size:       0x119,
					Entropy:    7.186678878967755,
					VarEntropy: 0.0023487100483950583,
				},
				Section{
					Name:       ".zdebug_line",
					Size:       0x1b8ac,
					Entropy:    7.991399871405648,
					VarEntropy: 2.1037107874221076e-07,
				},
				Section{
					Name:       ".zdebug_frame",
					Size:       0x5526,
					Entropy:    7.922440004034238,
					VarEntropy: 1.016144764855772e-05,
				},
				Section{
					Name:       ".debug_gdb_scripts",
					Size:       0x2c,
					Entropy:    4.265583322887733,
					VarEntropy: 0.01731684668465522,
				},
				Section{
					Name:       ".zdebug_info",
					Size:       0x31a5e,
					Entropy:    7.995541426118696,
					VarEntropy: 6.267550488793614e-08,
				},
				Section{
					Name:       ".zdebug_loc",
					Size:       0x198ca,
					Entropy:    7.98781739055232,
					VarEntropy: 3.42170689161735e-07,
				},
				Section{
					Name:       ".zdebug_ranges",
					Size:       0x8fac,
					Entropy:    7.784901524718818,
					VarEntropy: 1.6544706982903474e-05,
				},
				Section{
					Name:       ".note.go.buildid",
					Size:       0x64,
					Entropy:    5.267368784857279,
					VarEntropy: 0.011785373992272965,
				},
				Section{
					Name:       ".symtab",
					Size:       0xc5e8,
					Entropy:    3.20652780203368,
					VarEntropy: 0.0002942263172418581,
				},
				Section{
					Name:       ".strtab",
					Size:       0xb288,
					Entropy:    4.811184615055419,
					VarEntropy: 4.984016326397377e-05,
				},
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "-literals-tiny",
		}: symbolHashTestResults{
			hash: "f617fea3d4f7f43e80e200c8405084ae",
			imports: []string{
				"J5U4Po36.XWbBm1AJ",
				"J5U4Po36.XWbBm1AJ.func1",
				"J5U4Po36.ueJ06b5k",
				"J5U4Po36.ueJ06b5k.func1",
				"main.main",
				"main.main.func1",
			},
			entropy:  4.494293656279885,
			variance: 0.003947008480301743,
		},
		test{
			name:    "SectionStats",
			goos:    "plan9",
			builder: "go",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       "text",
					Size:       0x1108a8,
					Entropy:    5.881198482715571,
					VarEntropy: 7.124647426082509e-06,
				},
				Section{
					Name:       "data",
					Size:       0x17000,
					Entropy:    4.641107213427654,
					VarEntropy: 0.00015378291680262545,
				},
				Section{
					Name:       "syms",
					Size:       0xe9ac,
					Entropy:    5.09491297332817,
					VarEntropy: 8.573480749784487e-05,
				},
				Section{
					Name:       "spsz",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "pcsz",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
			},
		},
		test{
			name:    "SectionStats",
			goos:    "plan9",
			builder: "garble",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       "text",
					Size:       0x10fa88,
					Entropy:    5.877353366653366,
					VarEntropy: 7.179499001647305e-06,
				},
				Section{
					Name:       "data",
					Size:       0x17000,
					Entropy:    4.640950842399639,
					VarEntropy: 0.00015375648698920822,
				},
				Section{
					Name:       "syms",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "spsz",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
				Section{
					Name:       "pcsz",
					Size:       0x0,
					Entropy:    0.0,
					VarEntropy: 0.0,
				},
			},
		},
		test{
			name:    "SectionStats",
			goos:    "windows",
			builder: "go",
			flags:   "",
		}: sectionTestResults{
			sections: []Section{
				Section{
					Name:       ".text",
					Size:       0x8e400,
					Entropy:    6.1761252724928655,
					VarEntropy: 9.747108821196161e-06,
				},
				Section{
					Name:       ".rdata",
					Size:       0x9e600,
					Entropy:    5.138494981029609,
					VarEntropy: 1.6482890827748315e-05,
				},
				Section{
					Name:       ".data",
					Size:       0x17a00,
					Entropy:    4.601169638514693,
					VarEntropy: 0.0001514039073443931,
				},
				Section{
					Name:       ".zdebug_abbrev",
					Size:       0x200,
					Entropy:    4.829215920067953,
					VarEntropy: 0.024587620899965145,
				},
				Section{
					Name:       ".zdebug_line",
					Size:       0x1cc00,
					Entropy:    7.992417306885133,
					VarEntropy: 1.7899626019515757e-07,
				},
				Section{
					Name:       ".zdebug_frame",
					Size:       0x5800,
					Entropy:    7.9257471578709,
					VarEntropy: 9.304797839881427e-06,
				},
				Section{
					Name:       ".debug_gdb_scripts",
					Size:       0x200,
					Entropy:    0.7691902074556789,
					VarEntropy: 0.008919886275183865,
				},
				Section{
					Name:       ".zdebug_info",
					Size:       0x32a00,
					Entropy:    7.996420128772403,
					VarEntropy: 4.993294443511977e-08,
				},
				Section{
					Name:       ".zdebug_loc",
					Size:       0x1ba00,
					Entropy:    7.988932433866987,
					VarEntropy: 2.8483765422067984e-07,
				},
				Section{
					Name:       ".zdebug_ranges",
					Size:       0x9600,
					Entropy:    7.777719231416577,
					VarEntropy: 1.6851116730811515e-05,
				},
				Section{
					Name:       ".idata",
					Size:       0x600,
					Entropy:    3.6148445724061844,
					VarEntropy: 0.005141851830632267,
				},
				Section{
					Name:       ".reloc",
					Size:       0x6a00,
					Entropy:    5.440793703442042,
					VarEntropy: 2.360335708126473e-05,
				},
				Section{
					Name:       ".symtab",
					Size:       0x17800,
					Entropy:    5.133671236865931,
					VarEntropy: 6.743980706348455e-05,
				},
			},
		},
		test{
			name:    "GoSymbolHash",
			goos:    "windows",
			builder: "garble",
			flags:   "-literals",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "GoSymbolHash",
			goos:    "linux",
			builder: "garble",
			flags:   "-literals",
		}: symbolHashTestResults{
			hash:     "d41d8cd98f00b204e9800998ecf8427e",
			imports:  []string(nil),
			entropy:  0.0,
			variance: 0.0,
		},
		test{
			name:    "ImportHash",
			goos:    "darwin",
			builder: "garble",
			flags:   "-literals-tiny",
		}: importHashTestResults{
			hash: "d3ccf195b62a9279c3c19af1080497ec",
			imports: []string{
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
		},
	},
}
