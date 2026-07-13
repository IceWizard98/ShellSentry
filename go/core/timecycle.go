package core

import "math"

// TimeCycle maps seconds-into-day to unit-circle coords so 23:59 and 00:00
// are adjacent (lets Isolation Forest treat time as cyclic, not linear).
func TimeCycle(secondsIntoDay int) (cos, sin float64) {
	const day = 86400.0
	angle := 2 * math.Pi * float64(secondsIntoDay) / day
	return math.Cos(angle), math.Sin(angle)
}
