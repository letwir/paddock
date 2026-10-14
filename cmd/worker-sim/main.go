package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/letwir/paddock/internal/harness"
)

func main() {
	id := flag.String("id", "", "worker instance ID")
	coordinator := flag.String("coordinator", "", "loopback coordinator base URL")
	interval := flag.Duration("interval", time.Second, "poll interval")
	flag.Parse()
	if strings.TrimSpace(*id) == "" || *interval <= 0 {
		log.Fatal("-id and a positive -interval are required")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		response, err := harness.PullOnce(ctx, client, *coordinator, *id)
		cancel()
		if err != nil {
			log.Printf("worker=%s pull failed: %v", *id, err)
		} else {
			log.Printf("worker=%s coordinator=%s received=%d (simulator is idle; no work is executed)", *id, response.CoordinatorID, len(response.WorkItems))
		}
		time.Sleep(*interval)
	}
}
