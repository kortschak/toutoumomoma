// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"math"
	"math/rand"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/kortschak/utter"
)

var (
	generate    = flag.Bool("generate", false, "generate golden valued for tests")
	cleangolden = flag.Bool("clean", false, "reset golden values")
)

type test struct {
	name    string
	goos    string
	builder string
	flags   string
}

type importHashTestResults struct {
	// The Windows wantHashes value obtained by running the get_imphash function from
	// https://github.com/erocarrera/pefile and https://github.com/threatstream/symhash/
	// on the hello world executable.
	hash string
	// Obtained by inspection of debug/{elf,macho,pe,plan9obj} output.
	imports []string
}

type symbolHashTestResults struct {
	hash     string
	imports  []string
	entropy  float64
	variance float64
}

type sectionTestResults struct {
	sections []Section
}

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

	garble, err := garbleVersion()
	if err != nil {
		t.Fatal(err)
	}
	buildVersion := fmt.Sprintf("%s:%s", runtime.Version(), garble)
	if *cleangolden || goldenValues == nil {
		goldenValues = map[string]map[test]interface{}{}
	}
	if goldenValues[buildVersion] == nil {
		goldenValues[buildVersion] = map[test]interface{}{}
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

				test := test{goos: goos, builder: builder, flags: strings.Join(flags, " ")}

				t.Run(fmt.Sprintf("ImportHash_%s_%s_%v", goos, builder, strings.Join(flags, "_")), func(t *testing.T) {
					if !*generate && len(goldenValues[buildVersion]) == 0 {
						t.Skipf("no golden values for %s", buildVersion)
					}

					test.name = "ImportHash"
					golden, _ := goldenValues[buildVersion][test].(importHashTestResults)

					got, gotImports, err := ImportHash(target)
					if err != nil {
						t.Errorf("unexpected error hashing executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}
					if *generate {
						golden.hash = fmt.Sprintf("%x", got)
						golden.imports = gotImports
						goldenValues[buildVersion][test] = golden
					}
					if fmt.Sprintf("%x", got) != golden.hash {
						t.Errorf("unexpected hash for executable for GOOS=%s %s: got:%x want:%s",
							goos, cmd, got, golden.hash)
					}
					if !reflect.DeepEqual(gotImports, golden.imports) {
						t.Errorf("unexpected imports for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotImports, golden.imports)
					}
				})

				t.Run(fmt.Sprintf("GoSymbolHash_%s_%s_%v", goos, builder, strings.Join(flags, "_")), func(t *testing.T) {
					if !*generate && len(goldenValues[buildVersion]) == 0 {
						t.Skipf("no golden values for %s", buildVersion)
					}

					const (
						tolEnt = 0.3
						tolVar = 0.01
					)

					test.name = "GoSymbolHash"
					golden, _ := goldenValues[buildVersion][test].(symbolHashTestResults)

					got, gotSymbols, err := GoSymbolHash(target, false)
					if err != nil {
						t.Errorf("unexpected error hashing executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}
					gotEntropy, gotVariance := NameEntropy(gotSymbols)

					if *generate {
						golden.hash = fmt.Sprintf("%x", got)
						golden.imports = gotSymbols
						golden.entropy = gotEntropy
						golden.variance = gotVariance
						goldenValues[buildVersion][test] = golden
					}

					if (goos != "darwin" || builder != "garble") && fmt.Sprintf("%x", got) != golden.hash {
						t.Errorf("unexpected hash for executable for GOOS=%s %s: got:%x want:%s",
							goos, cmd, got, golden.hash)
					}

					if !reflect.DeepEqual(gotSymbols, golden.imports) && !hasMain(gotSymbols) {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotSymbols, golden.imports)
					}

					if math.Abs(gotEntropy-golden.entropy) > tolEnt {
						t.Errorf("unexpected symbol name entropy for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotEntropy, golden.entropy)
					}
					if math.Abs(gotVariance-golden.variance) > tolVar {
						t.Errorf("unexpected symbol name entropy for GOOS=%s %s: got:%v want:%v",
							goos, cmd, gotVariance, golden.variance)
					}
				})

				// Only test with and without garble.
				if len(flags) != 0 {
					continue
				}
				t.Run(fmt.Sprintf("SectionStats_%s_%s", goos, builder), func(t *testing.T) {
					if !*generate && len(goldenValues[buildVersion]) == 0 {
						t.Skipf("no golden values for %s", buildVersion)
					}

					const tol = 0.5

					// Included purely for regression testing. ELF values confirmed
					// by inspection of readelf output. We may expect these values
					// to change with different builder versions.
					test.name = "SectionStats"
					golden, _ := goldenValues[buildVersion][test].(sectionTestResults)

					got, err := Sections(target)
					if err != nil {
						t.Errorf("unexpected error examining executable imports for GOOS=%s %s: %v",
							goos, cmd, err)
						return
					}

					if *generate {
						golden.sections = got
						goldenValues[buildVersion][test] = golden
					}

					if wrong, ok := similarSections(got, golden.sections, tol); !ok {
						t.Errorf("unexpected symbols for GOOS=%s %s: got:%v want:%v",
							goos, cmd, got, golden.sections)
						if wrong >= 0 {
							t.Logf("%d: %+v != %v", wrong, got[wrong], golden.sections[wrong])
						}
					}
				})

			}
		}
	}
	os.Remove(target)

	if *generate {
		utter.Config.ElideType = true
		utter.Config.SortKeys = true
		utter.Config.LocalPackage = "toutoumomoma"
		var buf bytes.Buffer

		fmt.Fprintf(&buf, `// Code generate by go test -generate github.com/kortschak/toutoumomoma. DO NOT EDIT.

// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

// goldenValues is the list of known golden values keyed on Go and Garble version
// at the first level and test name in the second level.
var goldenValues = `)
		utter.Fdump(&buf, goldenValues)
		b, err := format.Source(buf.Bytes())
		if err != nil {
			t.Fatalf("unexpected error formatting golden value source: %v", err)
		}
		err = os.WriteFile("toutoumomoma_golden_test.go", b, 0o644)
		if err != nil {
			t.Fatalf("unexpected error writing golden value source: %v", err)
		}
	}
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
		if s.Flags != b[i].Flags {
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

func garbleVersion() (string, error) {
	cmd := exec.Command("garble", "version")
	var buf strings.Builder
	cmd.Stdout = &buf
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(buf.String())
	if v == "(devel)" {
		return "", errors.New("cannot run tests with development garble: run go install mvdan.cc/garble@latest")
	}
	return v, nil
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
