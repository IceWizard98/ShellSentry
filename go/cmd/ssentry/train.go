package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/spf13/cobra"

	"shellsentry/adapters/geomaxmind"
	"shellsentry/adapters/sqlitestore"
	"shellsentry/core"
	"shellsentry/ports"
)

// sessionStore is the subset of *sqlitestore.Store that trainSession needs;
// defined locally so retention/gate/flatten/matrix logic is unit-testable
// with a fake, without a real SQLite file. PruneAndLoad does the retention +
// load in a single transaction (one DB connection).
type sessionStore interface {
	PruneAndLoad(user string, keep int) (sessions []core.Session, pruned int, err error)
}

// trainCmd retrains the per-user Isolation Forest from stored sessions:
//   ssentry train --user alice --config /etc/ssentry/config.yaml
func trainCmd() *cobra.Command {
	var cfgPath, user string
	c := &cobra.Command{
		Use:   "train",
		Short: "Retrain the per-user Isolation Forest from stored sessions",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			if user == "" {
				return fmt.Errorf("--user is required")
			}
			if cfgPath == "" {
				cfgPath = os.Getenv("SSENTRY_CONFIG")
			}
			if cfgPath == "" {
				cfgPath = "config.yaml"
			}
			cfg, err := LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			// Preflight the Python trainer BEFORE touching the DB: if the
			// interpreter or its packages are missing, fail fast without pruning.
			pyBin, pyScript, err := resolvePython(cfg)
			if err != nil {
				return err
			}
			st := sqlitestore.New(cfg.RootPath)
			geo, err := geomaxmind.New(cfg.GeoIPDBPath)
			if err != nil {
				// geo is best-effort for training too: unknown country -> id 0.
				fmt.Fprintln(os.Stderr, "ssentry: geoip unavailable, training without geo:", err)
				return trainSession(cfg, user, nopGeo{}, st, pyBin, pyScript, os.Stdout)
			}
			defer geo.Close()
			return trainSession(cfg, user, geo, st, pyBin, pyScript, os.Stdout)
		},
	}
	c.Flags().StringVar(&user, "user", "", "user whose model to retrain (required)")
	c.Flags().StringVar(&cfgPath, "config", "", "path to config.yaml (or $SSENTRY_CONFIG)")
	return c
}

// resolvePython resolves the trainer interpreter and script from config
// (auto-defaulting when empty), verifies BOTH exist, and verifies the
// interpreter can import the required packages. It is a preflight: any failure
// returns a descriptive error so training aborts before mutating the DB.
func resolvePython(cfg Config) (bin, script string, err error) {
	// interpreter
	bin = cfg.PythonBin
	if bin == "" {
		venv := filepath.Join("python", "venv", "bin", "python")
		if _, e := os.Stat(venv); e == nil {
			bin = venv
		} else if p, e2 := exec.LookPath("python3"); e2 == nil {
			bin = p
		} else {
			return "", "", fmt.Errorf("no python interpreter: set python_bin or install python3: %w", e2)
		}
	} else if _, e := os.Stat(bin); e != nil {
		if p, e2 := exec.LookPath(bin); e2 == nil {
			bin = p
		} else {
			return "", "", fmt.Errorf("python_bin %q not found: %w", cfg.PythonBin, e)
		}
	}
	// trainer script
	script = cfg.TrainerScript
	if script == "" {
		script = filepath.Join("python", "trainer.py")
	}
	if _, e := os.Stat(script); e != nil {
		return "", "", fmt.Errorf("trainer script %q not found: %w", script, e)
	}
	// required packages must be importable by this interpreter
	check := exec.Command(bin, "-c", "import sklearn, numpy")
	if out, e := check.CombinedOutput(); e != nil {
		return "", "", fmt.Errorf("python %s cannot import required packages (scikit-learn, numpy) — run 'make venv': %w: %s", bin, e, out)
	}
	return bin, script, nil
}

// trainSession is the testable orchestrator: prune-to-max, gate on
// min_sessions_train, rebuild encoders + matrix in Go, then hand the matrix
// to the stateless Python trainer.
func trainSession(cfg Config, user string, geo ports.GeoResolver, st sessionStore, pythonBin, script string, out io.Writer) error {
	// 1. retention + load in a SINGLE transaction: prune oldest beyond
	// max_sessions_keep (keep<=0 -> no prune), then load the remaining sessions.
	sessions, pruned, err := st.PruneAndLoad(user, cfg.MaxSessionsKeep)
	if err != nil {
		return fmt.Errorf("prune+load: %w", err)
	}
	if pruned > 0 {
		fmt.Fprintf(out, "pruned %d old session(s) (keep %d)\n", pruned, cfg.MaxSessionsKeep)
	}

	// 2. gate: need at least min_sessions_train remaining
	if len(sessions) < cfg.MinSessionsTrain {
		fmt.Fprintf(out, "not enough sessions to train (%d/%d); skipping\n", len(sessions), cfg.MinSessionsTrain)
		return nil
	}

	// 3. rebuild encoders + matrix in Go
	rows := flattenRows(sessions, geo)
	if len(rows) == 0 {
		fmt.Fprintln(out, "no commands to train on; skipping")
		return nil
	}
	dicts := core.BuildDicts(rows)
	matrix := core.BuildMatrix(rows, dicts)

	// 4. write dicts.json (Go owns encoders; Python stays stateless)
	userDir := filepath.Join(cfg.RootPath, user)
	if err := os.MkdirAll(userDir, 0o700); err != nil {
		return fmt.Errorf("mkdir user dir: %w", err)
	}
	if err := writeJSON(filepath.Join(userDir, "dicts.json"), dicts); err != nil {
		return fmt.Errorf("write dicts: %w", err)
	}

	// 5. hand the matrix to the stateless Python trainer over stdin
	if err := runTrainer(pythonBin, script, userDir, matrix); err != nil {
		return fmt.Errorf("python trainer: %w", err)
	}
	fmt.Fprintf(out, "trained on %d commands from %d sessions -> %s\n", len(rows), len(sessions), userDir)
	return nil
}

// flattenRows resolves each command's country via geo.Country(ip) and reuses
// the stored time/spacing features verbatim.
func flattenRows(sessions []core.Session, geo ports.GeoResolver) []core.TrainRow {
	var rows []core.TrainRow
	for _, s := range sessions {
		for _, c := range s.Commands {
			country, _ := geo.Country(c.IP) // ""=unknown on error
			rows = append(rows, core.TrainRow{
				RawCmd:        c.RawCmd,
				Country:       country,
				TimeCos:       c.Feat.TimeCos,
				TimeSin:       c.Feat.TimeSin,
				SecsSinceLast: c.Feat.SecsSinceLast,
			})
		}
	}
	return rows
}

func runTrainer(pythonBin, script, outDir string, matrix [][]float64) error {
	payload, err := json.Marshal(map[string]any{"features": matrix})
	if err != nil {
		return fmt.Errorf("marshal matrix: %w", err)
	}
	cmd := exec.Command(pythonBin, script, "--outdir", outDir)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("run %s: %w", pythonBin, err)
	}
	return nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		return fmt.Errorf("write file: %w", err)
	}
	return nil
}
