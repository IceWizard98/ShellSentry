package core

import (
	"reflect"
	"testing"
)

func TestBuildDicts_And_Matrix(t *testing.T) {
	rows := []TrainRow{
		{RawCmd: "cat /etc/passwd", Country: "IT", TimeCos: 1, TimeSin: 0, SecsSinceLast: 5},
		{RawCmd: "cat /etc/passwd", Country: "IT", TimeCos: 1, TimeSin: 0, SecsSinceLast: 2},
		{RawCmd: "whoami", Country: "US", TimeCos: 0, TimeSin: 1, SecsSinceLast: 9},
	}
	d := BuildDicts(rows)

	// command ids 1-based, first-seen order
	if d.Command["cat"] != 1 || d.Command["whoami"] != 2 {
		t.Fatalf("command dict wrong: %v", d.Command)
	}
	if d.Country["IT"] != 1 || d.Country["US"] != 2 {
		t.Fatalf("country dict wrong: %v", d.Country)
	}
	// path frequency: /etc/passwd appears twice
	if d.Path["/etc/passwd"] != 2 {
		t.Fatalf("path freq wrong: %v", d.Path)
	}

	m := BuildMatrix(rows, d)
	if len(m) != 3 {
		t.Fatalf("matrix rows=%d want 3", len(m))
	}
	// row 0: [1,0, geo=1, cmd=1, path=2, secs=5]
	if !reflect.DeepEqual(m[0], []float64{1, 0, 1, 1, 2, 5}) {
		t.Fatalf("row0=%v", m[0])
	}
	// row 2: whoami has no path -> NoPathIndex; geo US=2, cmd=2
	if m[2][2] != 2 || m[2][3] != 2 || m[2][4] != float64(NoPathIndex) {
		t.Fatalf("row2=%v", m[2])
	}
}

func TestBuildDicts_EmptyCountryStaysUnknown(t *testing.T) {
	rows := []TrainRow{{RawCmd: "ls", Country: "", TimeCos: 1, TimeSin: 0}}
	d := BuildDicts(rows)
	if _, ok := d.Country[""]; ok {
		t.Fatal("empty country must not get an id (stays 0=unknown)")
	}
	m := BuildMatrix(rows, d)
	if m[0][2] != 0 {
		t.Fatalf("unknown country geo_id must be 0, got %v", m[0][2])
	}
}
