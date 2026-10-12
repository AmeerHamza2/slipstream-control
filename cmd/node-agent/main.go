// Command node-agent runs on every Slipstream VPN node.
//
// It keeps the node's WireGuard peers in sync with the api (who is entitled
// and was issued this node) and serves the health endpoints the fleet prober
// measures: a UDP echo port beside the WireGuard port and an HTTP /load.
// See package nodeagent.
//
// Configuration (environment):
//
//	API_URL               api base URL                         (required)
//	SERVER_ID             this node's id from POST /admin/v1/servers (required)
//	AGENT_TOKEN           bearer token for the peers endpoint  (required)
//	WG_INTERFACE          WireGuard interface                  (default wg0)
//	SYNC_INTERVAL         incremental sync interval            (default 15s)
//	FULL_RESYNC_INTERVAL  drift-repair full sync interval      (default 1h)
//	ECHO_ADDR             UDP echo health port                 (default :51821, i.e. wg_port+1)
//	HTTP_ADDR             /load /healthz /metrics              (default :9100)
//	PEER_CAPACITY         peers at which /load reports 1.0     (default 0: CPU load only)
//	PSK_DIR               dir for transient preshared-key files (default $TMPDIR; use a tmpfs)
//
// Flags:
//
//	-dry-run   keep the peer table in memory and log each change instead of
//	           calling wg(8); for demos and for checking an agent against an
//	           api before giving it a real interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ameerhamza2/slipstream-control/internal/nodeagent"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "node-agent:", err)
		os.Exit(1)
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func durEnv(k string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration like 15s", k)
	}
	return d, nil
}

func run() error {
	dryRun := flag.Bool("dry-run", false, "log peer changes instead of applying them with wg(8)")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})).With("service", "node-agent")

	var problems []error
	apiURL, serverID, token := os.Getenv("API_URL"), os.Getenv("SERVER_ID"), os.Getenv("AGENT_TOKEN")
	if apiURL == "" {
		problems = append(problems, errors.New("API_URL is required"))
	}
	if serverID == "" {
		problems = append(problems, errors.New("SERVER_ID is required"))
	}
	if token == "" {
		problems = append(problems, errors.New("AGENT_TOKEN is required"))
	}
	interval, err := durEnv("SYNC_INTERVAL", 15*time.Second)
	if err != nil {
		problems = append(problems, err)
	}
	fullEvery, err := durEnv("FULL_RESYNC_INTERVAL", time.Hour)
	if err != nil {
		problems = append(problems, err)
	}
	capacity, err := strconv.Atoi(env("PEER_CAPACITY", "0"))
	if err != nil || capacity < 0 {
		problems = append(problems, errors.New("PEER_CAPACITY must be a non-negative integer"))
	}
	if len(problems) > 0 {
		return errors.Join(problems...)
	}

	var applier nodeagent.Applier
	if *dryRun {
		m := nodeagent.NewMemoryApplier()
		m.Log = func(action string, p nodeagent.AppliedPeer) {
			// Public keys are pseudonymous device identifiers: log a short
			// prefix only. Preshared keys are never logged.
			log.Info("dry-run peer change", "action", action, "peer", short(p.PublicKey), "allowed_ip", p.AllowedIP)
		}
		applier = m
	} else {
		applier = &nodeagent.WGApplier{Interface: env("WG_INTERFACE", "wg0"), TempDir: os.Getenv("PSK_DIR")}
	}

	agent := &nodeagent.Agent{
		Source:          &nodeagent.Client{BaseURL: apiURL, ServerID: serverID, Token: token},
		Applier:         applier,
		Log:             log,
		Interval:        interval,
		FullResyncEvery: fullEvery,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pc, err := net.ListenPacket("udp", env("ECHO_ADDR", ":51821"))
	if err != nil {
		return fmt.Errorf("echo port: %w", err)
	}
	load := nodeagent.MaxLoad(nodeagent.CPULoad(), nodeagent.PeerLoad(agent, capacity))
	srv := nodeagent.NewHTTPServer(env("HTTP_ADDR", ":9100"), nodeagent.Handler(agent, load))

	errs := make(chan error, 3)
	go func() { errs <- nodeagent.ServeEcho(ctx, pc) }()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errs <- fmt.Errorf("http: %w", err)
		}
	}()
	go func() { errs <- agent.Run(ctx) }()
	log.Info("node agent started", "server_id", serverID, "dry_run", *dryRun, "echo", pc.LocalAddr().String(), "http", srv.Addr)

	select {
	case <-ctx.Done():
	case err := <-errs:
		if err != nil {
			log.Error("component failed", "error", err.Error())
		}
	}
	stop()
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdown)
	log.Info("node agent stopped")
	return nil
}

func short(k string) string {
	if len(k) > 8 {
		return k[:8] + "…"
	}
	return k
}
