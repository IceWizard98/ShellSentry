package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"shellsentry/adapters/alertsock"
	"shellsentry/adapters/geomaxmind"
	"shellsentry/adapters/ptyshell"
	"shellsentry/adapters/scorerclient"
	"shellsentry/adapters/sqlitestore"
	"shellsentry/adapters/totpauth"
	"shellsentry/core"
	"shellsentry/ports"
)

// nopGeo is the graceful-degradation GeoResolver used when the GeoIP DB is
// unavailable: every lookup is unknown ("" -> geo_id 0).
type nopGeo struct{}

func (nopGeo) Country(string) (string, error) { return "", nil }

// randNonce returns a cryptographically random hex nonce for the per-command
// sentinel marker, so command output cannot spoof the marker.
func randNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate sentinel nonce: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

func main() {
	if err := rootCmd().Execute(); err != nil {
		os.Exit(1) // main is the only place os.Exit is allowed; cobra printed the error
	}
}

// rootCmd builds the ssentry command tree. The `run` subcommand is the SSH
// ForceCommand entrypoint; future subcommands (e.g. `prune`, spec 3) attach here.
func rootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "ssentry",
		Short:         "SSH command anomaly-detection shell wrapper",
		SilenceUsage:  true, // runtime failures shouldn't dump usage text
		SilenceErrors: false,
	}
	root.AddCommand(runCmd())
	root.AddCommand(trainCmd())
	return root
}

// runCmd is the per-session runtime: set it as the SSH ForceCommand, e.g.
//
//	ForceCommand /usr/local/bin/ssentry run --config /etc/ssentry/config.yaml
func runCmd() *cobra.Command {
	var cfgPath string
	c := &cobra.Command{
		Use:   "run",
		Short: "Run the ForceCommand shell wrapper for the current SSH session",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cfgPath == "" {
				cfgPath = os.Getenv("SSENTRY_CONFIG")
			}
			if cfgPath == "" {
				cfgPath = "config.yaml"
			}
			return runSession(cfgPath)
		},
	}
	c.Flags().StringVar(&cfgPath, "config", "", "path to config.yaml (falls back to $SSENTRY_CONFIG, then ./config.yaml)")
	return c
}

func runSession(cfgPath string) error {
	// Catch SIGINT so Ctrl-C cannot kill ssentry and drop the user to a raw shell
	// or abandon an unsaved session — the monitored session must only end via
	// `exit`/EOF (clean, persisted) or a real disconnect (SIGHUP/SIGTERM, not
	// persisted). The signal is CAUGHT (not ignored via SIG_IGN): /bin/sh and its
	// children reset to the default handler on exec, so commands stay
	// interruptible; ssentry itself just drains it.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT)
	go func() {
		for range sigCh {
		}
	}()

	cfg, err := LoadConfig(cfgPath)
	if err != nil {
		return err
	}

	u, err := user.Current()
	if err != nil {
		return fmt.Errorf("current user: %w", err)
	}
	username := u.Username
	ip := clientIP() // from SSH_CONNECTION
	sessionID := fmt.Sprintf("%d", time.Now().UnixNano())

	novSev := cfg.NoveltySev()
	dicts, softThr, hardThr := loadUserArtifacts(cfg.RootPath, username)
	rules := loadRules(cfg.RulesPath)

	var geo ports.GeoResolver
	if g, err := geomaxmind.New(cfg.GeoIPDBPath); err != nil {
		// Graceful degradation: a missing/broken GeoIP DB must not lock the
		// user out of a shell. Fall back to a no-op resolver (geo_id 0).
		fmt.Fprintln(os.Stderr, "ssentry: geoip unavailable, continuing without geo:", err)
		geo = nopGeo{}
	} else {
		geo = g
		defer func() { _ = g.Close() }() // release the mmap'd GeoIP reader
	}

	otp := totpauth.New(cfg.RootPath, "shellsentry", os.Stdin, os.Stdout)
	if err := otp.EnsureProvisioned(username); err != nil {
		return err
	}

	nonce, err := randNonce()
	if err != nil {
		return err
	}
	shell, err := ptyshell.New(nonce, os.Stdin, os.Stdout, cfg.CommandTimeoutDur())
	if err != nil {
		return err
	}
	defer shell.Close()

	d := Deps{
		Scorer:          scorerclient.New(cfg.DaemonAddr),
		Store:           sqlitestore.New(cfg.RootPath),
		Geo:             geo,
		Alerter:         alertsock.New(cfg.AlertSocket),
		OTP:             otp,
		Shell:           shell,
		Rules:           rules,
		Dicts:           dicts,
		SoftThr:         softThr,
		HardThr:         hardThr,
		OTPRetries:      cfg.OTPRetries,
		ScoreTimeout:    cfg.ScoreTimeoutDur(),
		Now:             func() int64 { return time.Now().Unix() },
		NoveltySeverity: novSev,
	}

	// Single tty owner: os.Stdin feeds BOTH the command prompt and the OTP
	// prompt. On a real tty we drive term.Terminal (line history via up/down,
	// Tab autocomplete) over an UNBUFFERED 1-byte reader so it never reads past a
	// newline — otherwise it would steal type-ahead bytes from ptyshell, which
	// reads the same raw fd directly during RunCommand (breaking vi/top/etc.).
	// Off a tty (tests, pipes) we fall back to the plain byte-wise reader.
	var lr LineReader
	if term.IsTerminal(int(os.Stdin.Fd())) {
		// Put the outer tty in raw mode for the whole REPL: term.Terminal owns
		// echo/editing at the prompt. Set AFTER OTP provisioning (which runs in
		// cooked mode for QR + first code) and BEFORE the loop. ptyshell toggles
		// its own per-command raw mode and restores to this state (makeRawPolling
		// captures the current termios), so this stays in effect between commands.
		old, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return fmt.Errorf("set terminal raw mode: %w", err)
		}
		defer func() { _ = term.Restore(int(os.Stdin.Fd()), old) }()
		tlr := newTermLineReader(os.Stdin, os.Stdout, dicts)
		// Size the line editor to the real terminal (default is 80) and keep it in
		// sync on window resize, so the prompt lands at the right column after wide
		// command output. ptyshell sizes the pty itself (see ptyshell.New).
		if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
			tlr.SetSize(w, h)
		}
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		go func() {
			for range winch {
				if w, h, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
					tlr.SetSize(w, h)
				}
			}
		}()
		lr = tlr
	} else {
		lr = &plainLineReader{in: os.Stdin, out: os.Stdout}
	}
	s := RunREPL(username, ip, sessionID, lr, d)
	// Persist only clean, non-empty sessions: a session with no commands (e.g.
	// the user connected and immediately exited, or first-login provisioning)
	// carries no training signal and would only clutter the per-user DB.
	if s.Valid && len(s.Commands) > 0 {
		if err := d.Store.SaveSession(username, s); err != nil {
			return fmt.Errorf("save session: %w", err)
		}
	}
	return nil
}

func clientIP() string {
	// SSH_CONNECTION = "client_ip client_port server_ip server_port"
	parts := strings.Fields(os.Getenv("SSH_CONNECTION"))
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// loadUserArtifacts reads dicts.json + thresholds.json; missing -> empty dicts
// and pass-through thresholds (only rules gate). Never fails the session.
func loadUserArtifacts(root, user string) (core.Dicts, float64, float64) {
	var d core.Dicts
	dictsPath := userFile(root, user, "dicts.json")
	if raw, err := os.ReadFile(dictsPath); err == nil {
		if err := json.Unmarshal(raw, &d); err != nil {
			// Present but unparseable: warn and fall back to empty dicts
			// (unknown cmd/geo -> 0) rather than silently disabling scoring.
			fmt.Fprintf(os.Stderr, "ssentry: dicts file %s present but unparseable, ignoring: %v\n", dictsPath, err)
			d = core.Dicts{}
		}
	}
	// No model -> the -1e18 sentinel keeps every score above threshold, so
	// nothing is ever flagged by the model alone.
	soft, hard := -1e18, -1e18
	thrPath := userFile(root, user, "thresholds.json")
	if raw, err := os.ReadFile(thrPath); err == nil {
		// Pointer fields distinguish absent from present-but-zero: a thresholds
		// file of `{}` or missing soft/hard must NOT collapse to 0.0 (which would
		// spuriously hard-challenge every command); keep the safe sentinel.
		var th struct {
			Soft *float64 `json:"soft"`
			Hard *float64 `json:"hard"`
		}
		if err := json.Unmarshal(raw, &th); err != nil {
			fmt.Fprintf(os.Stderr, "ssentry: thresholds file %s present but unparseable, ignoring: %v\n", thrPath, err)
		} else if th.Soft != nil && th.Hard != nil {
			soft, hard = *th.Soft, *th.Hard
		} else {
			fmt.Fprintf(os.Stderr, "ssentry: thresholds file %s present but incomplete (missing soft/hard), keeping no-model sentinel\n", thrPath)
		}
	}
	return d, soft, hard
}

func loadRules(path string) core.Rules {
	var r core.Rules
	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &r); err != nil {
			// Present but unparseable: warn and fall back to empty rules rather
			// than silently disabling the admin pre-filter.
			fmt.Fprintf(os.Stderr, "ssentry: rules file %s present but unparseable, ignoring: %v\n", path, err)
			r = core.Rules{}
		}
	}
	return r
}

func userFile(root, user, name string) string {
	return root + "/" + user + "/" + name
}
