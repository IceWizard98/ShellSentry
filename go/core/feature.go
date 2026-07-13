package core

// Dicts are the per-user encoders produced by training; read-only at runtime.
type Dicts struct {
	Country map[string]int `json:"country"`
	Command map[string]int `json:"command"`
	Path    map[string]int `json:"path"`
}

func (d Dicts) GeoID(country string) int  { return d.Country[country] } // miss -> 0
func (d Dicts) CmdIndex(cmd string) int    { return d.Command[cmd] }     // miss -> 0

// PathIndex: no path -> NoPathIndex; unknown path -> 0; known -> its freq code.
func (d Dicts) PathIndex(path string, hasPath bool) int {
	if !hasPath {
		return NoPathIndex
	}
	return d.Path[path]
}

// Feature is the per-command vector sent to the scorer and stored in SQLite.
type Feature struct {
	TimeCos       float64 `json:"time_cos"`
	TimeSin       float64 `json:"time_sin"`
	GeoID         int     `json:"geo_id"`
	CmdIndex      int     `json:"cmd_index"`
	PathIndex     int     `json:"path_index"`
	SecsSinceLast int     `json:"secs_since_last"`
}

func BuildFeature(d Dicts, secondsIntoDay int, country, cmd string, args []string, secsSinceLast int) Feature {
	cos, sin := TimeCycle(secondsIntoDay)
	path, has := DetectPath(args)
	return Feature{
		TimeCos: cos, TimeSin: sin,
		GeoID:         d.GeoID(country),
		CmdIndex:      d.CmdIndex(cmd),
		PathIndex:     d.PathIndex(path, has),
		SecsSinceLast: secsSinceLast,
	}
}
