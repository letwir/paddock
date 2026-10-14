package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/letwir/paddock/internal/harness"
)

func main() {
	id := flag.String("id", "", "coordinator instance ID")
	listen := flag.String("listen", "127.0.0.1:0", "loopback listen address")
	flag.Parse()
	if strings.TrimSpace(*id) == "" {
		log.Fatal("-id is required")
	}
	addr, err := net.ResolveTCPAddr("tcp", *listen)
	if err != nil || !addr.IP.IsLoopback() {
		log.Fatal("-listen must be an explicit loopback IP address")
	}
	dsn := os.Getenv("PADDOCK_DB_URL")
	if dsn == "" {
		log.Fatal("PADDOCK_DB_URL is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		cancel()
		log.Fatal("invalid PADDOCK_DB_URL")
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		cancel()
		log.Fatal("unable to open database pool")
	}
	var database string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&database); err != nil {
		cancel()
		pool.Close()
		log.Fatal("unable to verify database identity")
	}
	cancel()
	if database != "paddock_test" {
		pool.Close()
		log.Fatal("refusing to start against unexpected database")
	}
	handler, err := harness.NewCoordinatorHandler(*id, pool)
	if err != nil {
		pool.Close()
		log.Fatal(err)
	}
	listener, err := net.Listen("tcp", addr.String())
	if err != nil {
		pool.Close()
		log.Fatal("unable to listen")
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second}
	log.Printf("coordinator=%s listen=%s database=paddock_test", *id, listener.Addr())
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-signalCtx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("server shutdown: %v", err)
		}
	}()
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		pool.Close()
		log.Fatal("coordinator server failed")
	}
	pool.Close()
}
