package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Yonsm/misgo"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, filepath.Base(os.Args[0]), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	cancel()
	os.Exit(code)
}

func run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	verbosity := 3
	if len(args) > 0 && strings.HasPrefix(args[0], "-v") {
		verbosity = 4
		if len(args[0]) > 2 {
			digit := args[0][2]
			if digit < '0' || digit > '9' {
				fmt.Fprintf(stderr, "ValueError: invalid literal for int() with base 10: '%c'\n", digit)
				return 1
			}
			verbosity = min(int(digit-'0'), 5)
		}
		args = args[1:]
	}
	prefix := name + " "
	if len(args) == 0 {
		usage(stdout, prefix)
		return 0
	}
	levels := [...]slog.Level{100, 12, slog.LevelError, slog.LevelWarn, slog.LevelInfo, slog.LevelDebug}
	logger := slog.New(newLogHandler(stderr, levels[verbosity]))
	cfg := misgo.ConfigFromEnv()
	text := strings.Join(args, " ")
	if cfg.Local != "" {
		address, token, err := cfg.LocalTarget()
		if err != nil {
			fmt.Fprintln(stderr, "Error:", err)
			return 1
		}
		local, err := misgo.NewMiIOLocalService(address, token)
		if err != nil {
			return report(stderr, logger, err)
		}
		result, err := misgo.LocalCommand(ctx, local, text, prefix)
		if err == nil {
			err = printResult(stdout, result)
		}
		return report(stderr, logger, err)
	}
	path, err := misgo.HomeTokenPath()
	if err != nil {
		return report(stderr, logger, err)
	}
	reader := bufio.NewReader(stdin)
	account := misgo.NewMiAccount(cfg.Username, cfg.Password,
		misgo.WithTokenPath(path), misgo.WithLogger(logger),
		misgo.WithOTPCallback(func(ctx context.Context, method string) (string, error) {
			fmt.Fprintf(stdout, "Input %s Code: ", method)
			type input struct {
				line string
				err  error
			}
			ready := make(chan input, 1)
			go func() {
				line, err := reader.ReadString('\n')
				ready <- input{line, err}
			}()
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case got := <-ready:
				if got.err == io.EOF && got.line == "" {
					return "", fmt.Errorf("No interactive terminal for OTP input. Provide an otp_callback to MiAccount.")
				}
				if got.err != nil && got.err != io.EOF {
					return "", got.err
				}
				return strings.TrimSuffix(strings.TrimSuffix(got.line, "\n"), "\r"), nil
			}
		}),
	)
	defer account.Close()
	if text == "mina" || strings.HasPrefix(text, "mina ") {
		code, err := runMina(ctx, misgo.NewMiNAService(account), strings.TrimPrefix(text, "mina"), cfg.DID, stdout, stderr)
		if err != nil {
			return report(stderr, logger, err)
		}
		return code
	}
	result, err := misgo.Command(ctx, misgo.NewMiIOService(account, ""), cfg.DID, text, prefix)
	if err == nil {
		err = printResult(stdout, result)
	}
	return report(stderr, logger, err)
}

func usage(w io.Writer, prefix string) {
	fmt.Fprintf(w, "MisGo %s - XiaoMi Cloud Service\n\n", misgo.Version)
	fmt.Fprintln(w, "Usage: The following variables must be set:")
	fmt.Fprintln(w, "           export MI_USER=<Username>")
	fmt.Fprintln(w, "           export MI_PASS=<Password>")
	fmt.Fprint(w, "           export MI_DID=<Device ID|Name>\n\n")
	fmt.Fprintln(w, misgo.CommandHelp("", prefix))
	fmt.Fprintln(w, "MiNA Commands:")
	for _, item := range minaHelp {
		fmt.Fprintf(w, "           %smina %-11s%s\n", prefix, item.command, item.description)
	}
	fmt.Fprint(w, "\nLocal Device (no cloud account, direct LAN control):\n")
	fmt.Fprint(w, "           export MI_LOCAL=<IP>:<Token>\n\n")
	fmt.Fprintln(w, misgo.LocalCommandHelp(prefix))
}

func printResult(w io.Writer, value any) error {
	if text, ok := value.(string); ok {
		_, err := fmt.Fprintln(w, text)
		return err
	}
	return printJSON(w, value)
}

func printJSON(w io.Writer, value any) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return err
	}
	_, err := buf.WriteTo(w)
	return err
}

func report(w io.Writer, logger *slog.Logger, err error) int {
	if err == nil {
		return 0
	}
	logger.Error("Error: " + err.Error())
	fmt.Fprintln(w, err)
	return 1
}

func newLogHandler(w io.Writer, level slog.Level) slog.Handler {
	return lineHandler{out: w, level: level, mu: new(sync.Mutex)}
}

// lineHandler emits the unadorned messages used by MiService's CLI logger.
type lineHandler struct {
	out   io.Writer
	level slog.Level
	mu    *sync.Mutex
	group string
	attrs string
}

func (h lineHandler) Enabled(_ context.Context, level slog.Level) bool { return level >= h.level }

func (h lineHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	var line strings.Builder
	for _, a := range attrs {
		h.writeAttr(&line, a)
	}
	h.attrs += line.String()
	return h
}

func (h lineHandler) WithGroup(name string) slog.Handler {
	if name != "" {
		h.group += name + "."
	}
	return h
}

func (h lineHandler) Handle(_ context.Context, r slog.Record) error {
	var line strings.Builder
	line.WriteString(r.Message)
	line.WriteString(h.attrs)
	r.Attrs(func(a slog.Attr) bool {
		h.writeAttr(&line, a)
		return true
	})
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprintln(h.out, line.String())
	return err
}

func (h lineHandler) writeAttr(w io.Writer, a slog.Attr) {
	if !a.Equal(slog.Attr{}) {
		fmt.Fprintf(w, " %s%s=%v", h.group, a.Key, a.Value.Resolve())
	}
}
