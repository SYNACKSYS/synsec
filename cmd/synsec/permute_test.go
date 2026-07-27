package main

import (
	"flag"
	"reflect"
	"testing"
)

func newTestFlagSet() *flag.FlagSet {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("data", "", "")
	fs.String("value", "", "")
	fs.Bool("write", false, "")
	return fs
}

func TestPermuteAcceptsBothOrders(t *testing.T) {
	cases := map[string]struct {
		args     []string
		wantArgs []string // positional arguments after parsing
	}{
		"options first": {
			args:     []string{"-data", "d", "Maison", "/mqtt"},
			wantArgs: []string{"Maison", "/mqtt"},
		},
		"options last": {
			args:     []string{"Maison", "/mqtt", "-data", "d"},
			wantArgs: []string{"Maison", "/mqtt"},
		},
		"options interleaved": {
			args:     []string{"Maison", "-data", "d", "/mqtt", "-value", "x"},
			wantArgs: []string{"Maison", "/mqtt"},
		},
		"boolean takes no value": {
			args:     []string{"Maison", "-write", "/mqtt"},
			wantArgs: []string{"Maison", "/mqtt"},
		},
		"equals form": {
			args:     []string{"Maison", "-data=d", "/mqtt"},
			wantArgs: []string{"Maison", "/mqtt"},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			fs := newTestFlagSet()
			if err := fs.Parse(permute(fs, tc.args)); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if got := fs.Args(); !reflect.DeepEqual(got, tc.wantArgs) {
				t.Fatalf("positional arguments are %v, want %v", got, tc.wantArgs)
			}
		})
	}
}

func TestPermuteReadsOptionValues(t *testing.T) {
	fs := newTestFlagSet()
	if err := fs.Parse(permute(fs, []string{"Maison", "/mqtt", "-value", "s3cr3t", "-write"})); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if got := fs.Lookup("value").Value.String(); got != "s3cr3t" {
		t.Fatalf("value is %q, want s3cr3t", got)
	}
	if got := fs.Lookup("write").Value.String(); got != "true" {
		t.Fatalf("write is %q, want true", got)
	}
}

// A secret value that begins with a dash must survive being passed after "--",
// or a password like "-abc" would be read as an unknown option.
func TestPermuteHonoursDoubleDash(t *testing.T) {
	fs := newTestFlagSet()
	if err := fs.Parse(permute(fs, []string{"-data", "d", "--", "-pas-une-option"})); err != nil {
		t.Fatalf("Parse: %v", err)
	}

	want := []string{"-pas-une-option"}
	if got := fs.Args(); !reflect.DeepEqual(got, want) {
		t.Fatalf("positional arguments are %v, want %v", got, want)
	}
}
