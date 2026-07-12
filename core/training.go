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

// BuildDicts rebuilds the per-user encoders from a training set. Command,
// country, and path all use FREQUENCY encoding (occurrence count): a higher
// count means a more common — hence more normal — item, so a rare or never-seen
// item lands in the sparse low region the model flags as anomalous. An arbitrary
// id carries no such signal (id 5 is not "more normal" than id 1), so it is not
// used.
//   - command: cmd word -> occurrence count (0 = unseen at runtime)
//   - country: code -> occurrence count ("" skipped -> 0 = unknown at runtime)
//   - path:    path -> occurrence count (0 = unseen; 9999999 = no path, at runtime)
func BuildDicts(rows []TrainRow) Dicts {
	d := Dicts{
		Country: map[string]int{},
		Command: map[string]int{},
		Path:    map[string]int{},
	}
	for _, r := range rows {
		cmd, args := SplitCommand(r.RawCmd)
		if cmd != "" {
			d.Command[cmd]++
		}
		if r.Country != "" {
			d.Country[r.Country]++
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
