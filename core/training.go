package core

// TrainRow is one command flattened for training: raw command, already-resolved
// country (""=unknown), and the time/spacing features reused verbatim from the DB.
type TrainRow struct {
	RawCmd        string
	Country       string
	TimeCos       float64
	TimeSin       float64
	SecsSinceLast int
}

// BuildDicts rebuilds the per-user encoders from a training set:
//   - command: cmd word -> id (ids start at 1, first-seen order; 0 = unseen at runtime)
//   - country: code -> id (ids start at 1; "" is skipped so it maps to 0 = unknown)
//   - path:    path -> occurrence count (frequency encoding)
func BuildDicts(rows []TrainRow) Dicts {
	d := Dicts{
		Country: map[string]int{},
		Command: map[string]int{},
		Path:    map[string]int{},
	}
	for _, r := range rows {
		cmd, args := SplitCommand(r.RawCmd)
		if cmd != "" {
			if _, ok := d.Command[cmd]; !ok {
				d.Command[cmd] = len(d.Command) + 1
			}
		}
		if r.Country != "" {
			if _, ok := d.Country[r.Country]; !ok {
				d.Country[r.Country] = len(d.Country) + 1
			}
		}
		if p, ok := DetectPath(args); ok {
			d.Path[p]++
		}
	}
	return d
}

// BuildMatrix turns rows into numeric feature vectors using the given encoders,
// in the exact column order the runtime and model expect:
// [time_cos, time_sin, geo_id, cmd_index, path_index, secs_since_last].
func BuildMatrix(rows []TrainRow, d Dicts) [][]float64 {
	m := make([][]float64, 0, len(rows))
	for _, r := range rows {
		cmd, args := SplitCommand(r.RawCmd)
		p, hasPath := DetectPath(args)
		m = append(m, []float64{
			r.TimeCos,
			r.TimeSin,
			float64(d.GeoID(r.Country)),
			float64(d.CmdIndex(cmd)),
			float64(d.PathIndex(p, hasPath)),
			float64(r.SecsSinceLast),
		})
	}
	return m
}
