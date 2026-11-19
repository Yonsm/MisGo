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
	"strconv"
	"strings"
	"sync"

	"github.com/Yonsm/misgo/account"
	"github.com/Yonsm/misgo/local"
	"github.com/Yonsm/misgo/miio"
	"github.com/Yonsm/misgo/miio/decode"
	"github.com/Yonsm/misgo/mina"
	"github.com/Yonsm/misgo/spec"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, filepath.Base(os.Args[0]), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
	if ctx.Err() != nil {
		code = 130
	}
	cancel()
	os.Exit(code)
}

func run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	verbosity := 3
	if len(args) > 0 && strings.HasPrefix(args[0], "-v") && args[0] != "-version" {
		verbosity = 4
		if suffix := args[0][2:]; suffix != "" {
			n, err := strconv.Atoi(suffix)
			if err != nil || n < 0 {
				fmt.Fprintf(stderr, "Error: invalid verbosity flag %q (use -v or -v0..-v5)\n", args[0])
				return 1
			}
			verbosity = min(n, 5)
		}
		args = args[1:]
	}
	if len(args) > 0 {
		switch args[0] {
		case "version", "--version", "-version", "-V":
			fmt.Fprintf(stdout, "misgo %s\n", Version)
			return 0
		}
	}
	prefix := name + " "
	if len(args) == 0 {
		usage(stdout, prefix)
		return 0
	}
	levels := [...]slog.Level{100, 12, slog.LevelError, slog.LevelWarn, slog.LevelInfo, slog.LevelDebug}
	logger := slog.New(newLogHandler(stderr, levels[verbosity]))
	cfg := ConfigFromEnv()
	text := strings.Join(args, " ")
	if cfg.Local != "" {
		address, token, err := cfg.LocalTarget()
		if err != nil {
			fmt.Fprintln(stderr, "Error:", err)
			return 1
		}
		svc, err := local.New(address, token)
		if err != nil {
			return report(stderr, err)
		}
		result, err := svc.Command(ctx, text, prefix)
		return reportResult(stdout, stderr, result, err)
	}
	cmd, arg, _ := strings.Cut(text, " ")
	if cmd == "spec" || cmd == "decode" {
		var argv [4]string
		copy(argv[:], strings.Fields(arg))
		var result any
		var err error
		if cmd == "spec" {
			result, err = spec.New(spec.WithIndexCache(spec.DefaultIndexCachePath())).Spec(ctx, argv[0], argv[1])
		} else if argv[0] == "" || argv[1] == "" || argv[2] == "" {
			err = fmt.Errorf("usage: decode <ssecurity> <nonce> <data> [gzip]")
		} else {
			result, err = decode.Decode(argv[0], argv[1], argv[2], argv[3] == "gzip")
		}
		return reportResult(stdout, stderr, result, err)
	}
	path, err := HomeTokenPath()
	if err != nil {
		return report(stderr, err)
	}
	reader := bufio.NewReader(stdin)
	acct := account.New(cfg.Username, cfg.Password,
		account.WithTokenPath(path),
		account.WithLogger(logger),
		account.WithOTPCallback(func(ctx context.Context, method string) (string, error) {
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
	defer acct.Close()
	if text == "mina" || strings.HasPrefix(text, "mina ") {
		code, err := runMina(ctx, mina.New(acct), strings.TrimPrefix(text, "mina"), cfg.DID, stdout, stderr)
		if err != nil {
			return report(stderr, err)
		}
		return code
	}
	result, err := miio.New(acct, "").Command(ctx, cfg.DID, text, prefix)
	return reportResult(stdout, stderr, result, err)
}

func usage(w io.Writer, prefix string) {
	fmt.Fprintf(w, "MisGo %s - XiaoMi Cloud Service\n\n", Version)
	fmt.Fprintln(w, "Usage: The following variables must be set:")
	fmt.Fprintln(w, "           export MI_USER=<Username>")
	fmt.Fprintln(w, "           export MI_PASS=<Password>")
	fmt.Fprint(w, "           export MI_DID=<Device ID|Name>\n\n")
	fmt.Fprintln(w, miio.Help("", prefix))
	fmt.Fprintln(w, "MiNA Commands:")
	for _, item := range minaHelp {
		fmt.Fprintf(w, "           %smina %-11s%s\n", prefix, item.command, item.description)
	}
	fmt.Fprint(w, "\nLocal Device (no cloud account, direct LAN control):\n")
	fmt.Fprint(w, "           export MI_LOCAL=<IP>:<Token>\n\n")
	fmt.Fprintln(w, local.Help(prefix))
	fmt.Fprintln(w, "Version:")
	fmt.Fprintf(w, "           %sversion\n", prefix)
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

func report(w io.Writer, err error) int {
	if err == nil {
		return 0
	}
	fmt.Fprintln(w, "Error:", err)
	return 1
}

func reportResult(stdout, stderr io.Writer, value any, err error) int {
	if err == nil {
		err = printResult(stdout, value)
	}
	return report(stderr, err)
}

func newLogHandler(w io.Writer, level slog.Level) slog.Handler {
	return lineHandler{out: w, level: level, mu: new(sync.Mutex)}
}

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
