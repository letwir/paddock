package harness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var ErrInvalidCoordinatorURL = errors.New("coordinator URL must use HTTP loopback")

type DatabaseProbe interface {
	Ping(context.Context) error
}

type PullRequest struct {
	WorkerID string `json:"worker_id"`
}

type PullResponse struct {
	CoordinatorID string   `json:"coordinator_id"`
	WorkerID      string   `json:"worker_id"`
	WorkItems     []string `json:"work_items"`
}

// NewCoordinatorHandler exposes only a health probe and an empty deterministic
// pull response. It is a local process-harness seam, not a Scheduler or lease API.
func NewCoordinatorHandler(id string, db DatabaseProbe) (http.Handler, error) {
	if strings.TrimSpace(id) == "" {
		return nil, errors.New("coordinator ID is required")
	}
	if db == nil {
		return nil, errors.New("coordinator DB probe is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := db.Ping(ctx); err != nil {
			http.Error(w, "database unavailable", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"coordinator_id": id, "status": "ready"})
	})
	mux.HandleFunc("POST /pull", func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var req PullRequest
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "invalid pull request", http.StatusBadRequest)
			return
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			http.Error(w, "request must contain one JSON object", http.StatusBadRequest)
			return
		}
		if req.WorkerID == "" || strings.TrimSpace(req.WorkerID) != req.WorkerID {
			http.Error(w, "worker_id is required", http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, PullResponse{CoordinatorID: id, WorkerID: req.WorkerID, WorkItems: []string{}})
	})
	return mux, nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

// PullOnce performs one worker pull against a loopback-only coordinator.
func PullOnce(ctx context.Context, client *http.Client, baseURL, workerID string) (PullResponse, error) {
	if client == nil {
		return PullResponse{}, errors.New("worker HTTP client is required")
	}
	if workerID == "" || strings.TrimSpace(workerID) != workerID {
		return PullResponse{}, errors.New("worker ID is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" || strings.ContainsAny(baseURL, "\\%\r\n\t ") || !isLoopbackHost(u.Hostname()) {
		return PullResponse{}, ErrInvalidCoordinatorURL
	}
	// Require the raw authority to be exactly the parsed authority. This rejects
	// parser-differential inputs (notably backslash userinfo/host confusion).
	if !strings.HasPrefix(baseURL, "http://") || strings.TrimPrefix(baseURL, "http://") != u.Host && strings.TrimPrefix(baseURL, "http://") != u.Host+"/" {
		return PullResponse{}, ErrInvalidCoordinatorURL
	}
	if port := u.Port(); port != "" {
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return PullResponse{}, ErrInvalidCoordinatorURL
		}
	}
	endpoint := "http://" + u.Host + "/pull"
	body, err := json.Marshal(PullRequest{WorkerID: workerID})
	if err != nil {
		return PullResponse{}, fmt.Errorf("encode worker pull: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return PullResponse{}, fmt.Errorf("create worker pull: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return PullResponse{}, fmt.Errorf("request coordinator pull: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return PullResponse{}, fmt.Errorf("coordinator pull returned HTTP %d", resp.StatusCode)
	}
	resp.Body = http.MaxBytesReader(nil, resp.Body, 8192)
	var result PullResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return PullResponse{}, fmt.Errorf("decode coordinator pull: %w", err)
	}
	if result.WorkerID != workerID || result.CoordinatorID == "" || result.WorkItems == nil {
		return PullResponse{}, errors.New("coordinator returned an invalid pull response")
	}
	return result, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
