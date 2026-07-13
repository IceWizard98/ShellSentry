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

	// command frequency: cat appears twice, whoami once
	if d.Command["cat"] != 2 || d.Command["whoami"] != 1 {
		t.Fatalf("command freq wrong: %v", d.Command)
	}
	// country frequency: IT appears twice, US once
	if d.Country["IT"] != 2 || d.Country["US"] != 1 {
		t.Fatalf("country freq wrong: %v", d.Country)
	}
	// path frequency: /etc/passwd appears twice
	if d.Path["/etc/passwd"] != 2 {
		t.Fatalf("path freq wrong: %v", d.Path)
	}

	m := BuildMatrix(rows, d)
	if len(m) != 3 {
		t.Fatalf("matrix rows=%d want 3", len(m))
	}
	// row 0: [1,0, geo_freq=2, cmd_freq=2, path_freq=2, secs=5]
	if !reflect.DeepEqual(m[0], []float64{1, 0, 2, 2, 2, 5}) {
		t.Fatalf("row0=%v", m[0])
	}
	// row 2: whoami has no path -> NoPathIndex; geo US_freq=1, cmd_freq=1
	if m[2][2] != 1 || m[2][3] != 1 || m[2][4] != float64(NoPathIndex) {
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
