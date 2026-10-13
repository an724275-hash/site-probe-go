package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/an724275-hash/site-probe-go/internal/probe"
)

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("siteprobe", flag.ContinueOnError)
	flags.SetOutput(stderr)
	file := flags.String("targets", "", "JSON file with targets")
	format := flags.String("format", "table", "table or json")
	timeout := flags.Duration("timeout", 10*time.Second, "timeout per target")
	workers := flags.Int("workers", 4, "parallel checks, 1 to 32")
	redirects := flags.Int("redirects", 5, "maximum redirects, 0 to 10")
	allowHTTP := flags.Bool("allow-http", false, "allow unencrypted HTTP")
	allowPrivate := flags.Bool("allow-private", false, "allow private addresses for local diagnostics")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintln(stderr, "format must be table or json")
		return 2
	}
	if *file != "" && flags.NArg() > 0 {
		fmt.Fprintln(stderr, "use either -targets or URL arguments")
		return 2
	}
	var targets []probe.Target
	if *file != "" {
		input, err := os.Open(*file)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		decoder := json.NewDecoder(io.LimitReader(input, 1024*1024+1))
		decoder.DisallowUnknownFields()
		err = decoder.Decode(&targets)
		if err == nil {
			var extra any
			if decoder.Decode(&extra) != io.EOF {
				err = errors.New("unexpected data after targets")
			}
		}
		input.Close()
		if err != nil {
			fmt.Fprintln(stderr, "invalid targets:", err)
			return 2
		}
	} else {
		for _, url := range flags.Args() {
			targets = append(targets, probe.Target{URL: url})
		}
	}
	if len(targets) == 0 || len(targets) > 100 {
		fmt.Fprintln(stderr, "provide between 1 and 100 targets")
		return 2
	}
	checker, err := probe.New(probe.Options{Timeout: *timeout, Workers: *workers, MaxRedirects: *redirects, AllowHTTP: *allowHTTP, AllowPrivate: *allowPrivate})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	results := checker.Run(ctx, targets)
	if *format == "json" {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		err = encoder.Encode(results)
	} else {
		writer := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(writer, "STATUS\tHTTP\tTOTAL MS\tTARGET")
		for _, result := range results {
			name := result.Name
			if name == "" {
				name = result.URL
			}
			name = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(name)
			fmt.Fprintf(writer, "%s\t%d\t%.1f\t%s\n", result.Status, result.StatusCode, result.Timings.TotalMS, name)
			if result.Error != "" {
				fmt.Fprintf(writer, "\t\t\t%s\n", probe.Summary(result))
			}
		}
		err = writer.Flush()
	}
	if err != nil {
		fmt.Fprintln(stderr, "could not write report:", err)
		return 2
	}
	for _, result := range results {
		if result.Status != "ok" {
			return 1
		}
	}
	return 0
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
