package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/hicancan/sdp-tunnel/internal/service"
)

// Set by the release build. A binary built by hand reports these defaults
// rather than claiming a version it is not.
var (
	Version   = "dev"
	GitCommit = "unknown"
	BuildDate = "unknown"
)

func main() {
	path := flag.String("c", "config.json", "configuration file")
	version := flag.Bool("v", false, "show build version")
	check := flag.Bool("check", false, "check cached authentication and the tunnel handshake without opening listeners or logging in")
	flag.Parse()
	if *version {
		fmt.Printf("sdp-tunnel %s (%s, %s)\n", Version, GitCommit, BuildDate)
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := service.Run(ctx, configPath(*path), *check); err != nil {
		log.Printf("sdp-tunnel: %v", err)
		os.Exit(1)
	}
}

// configPath lets a binary installed on PATH find a configuration left beside
// it, so it can be run from any directory. An explicit -c is always taken as
// given, and so is a file that exists where the caller is standing.
func configPath(path string) string {
	if filepath.IsAbs(path) || explicit("c") {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	exe, err := os.Executable()
	if err != nil {
		return path
	}
	beside := filepath.Join(filepath.Dir(exe), path)
	if _, err := os.Stat(beside); err != nil {
		return path
	}
	return beside
}

func explicit(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}
