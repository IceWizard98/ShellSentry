package core

import "testing"

func testDicts() Dicts {
	return Dicts{
		Country: map[string]int{"IT": 1, "US": 2},
		Command: map[string]int{"ls": 5, "cat": 6},
		Path:    map[string]int{"/etc/passwd": 3},
	}
}

func TestDicts_Lookups_MissIsZero(t *testing.T) {
	d := testDicts()
	if d.GeoID("IT") != 1 || d.GeoID("XX") != 0 {
		t.Fatal("geo lookup wrong")
	}
	if d.CmdIndex("ls") != 5 || d.CmdIndex("nmap") != 0 {
		t.Fatal("cmd lookup wrong")
	}
	if d.PathIndex("/etc/passwd", true) != 3 || d.PathIndex("/new", true) != 0 {
		t.Fatal("path lookup wrong")
	}
	if d.PathIndex("", false) != NoPathIndex {
		t.Fatal("no-path index wrong")
	}
}

func TestBuildFeature_Composes(t *testing.T) {
	d := testDicts()
	f := BuildFeature(d, 0, "IT", "cat", []string{"cat", "/etc/passwd"}, 42)
	if f.GeoID != 1 || f.CmdIndex != 6 || f.PathIndex != 3 || f.SecsSinceLast != 42 {
		t.Fatalf("bad feature: %+v", f)
	}
	if f.TimeCos != 1 || f.TimeSin != 0 {
		t.Fatalf("bad time encoding: %+v", f)
	}
}

func TestBuildFeature_NoPath(t *testing.T) {
	d := testDicts()
	f := BuildFeature(d, 0, "XX", "whoami", []string{"whoami"}, 0)
	if f.GeoID != 0 || f.CmdIndex != 0 || f.PathIndex != NoPathIndex {
		t.Fatalf("bad feature: %+v", f)
	}
}
