package geomaxmind

import "testing"

func TestCountry_InvalidIP_EmptyNoError(t *testing.T) {
	g := &Geo{} // reader nil path exercised: invalid IP returns "" before reader use
	c, err := g.Country("not-an-ip")
	if err != nil || c != "" {
		t.Fatalf("invalid ip: got %q err=%v want \"\",nil", c, err)
	}
}
