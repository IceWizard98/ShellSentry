package core

import (
	"math"
	"testing"
)

func TestTimeCycle_Midnight_IsAngleZero(t *testing.T) {
	cos, sin := TimeCycle(0)
	if math.Abs(cos-1) > 1e-9 || math.Abs(sin-0) > 1e-9 {
		t.Fatalf("midnight: got cos=%v sin=%v want 1,0", cos, sin)
	}
}

func TestTimeCycle_Noon_IsHalfCircle(t *testing.T) {
	cos, sin := TimeCycle(43200) // 12:00
	if math.Abs(cos-(-1)) > 1e-9 || math.Abs(sin-0) > 1e-9 {
		t.Fatalf("noon: got cos=%v sin=%v want -1,0", cos, sin)
	}
}

func TestTimeCycle_CrossDayContinuity(t *testing.T) {
	// 23:59:59 and 00:00:01 must be near each other on the circle.
	c1, s1 := TimeCycle(86399)
	c2, s2 := TimeCycle(1)
	if math.Hypot(c1-c2, s1-s2) > 1e-3 {
		t.Fatalf("cross-day discontinuity: %v,%v vs %v,%v", c1, s1, c2, s2)
	}
}
