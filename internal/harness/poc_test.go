package harness

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeDBProbe struct{ err error }

func TestCoordinatorExposesOnlyHealthAndPullRoutes(t *testing.T) {
	handler, err := NewCoordinatorHandler("coord-a", fakeDBProbe{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()

	for _, route := range []string{"/enroll", "/enrollment", "/challenge", "/register", "/registration", "/api/v1/enroll"} {
		t.Run(route, func(t *testing.T) {
			resp, err := server.Client().Get(server.URL + route)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("GET %s status=%d, want 404", route, resp.StatusCode)
			}
		})
	}

	for _, test := range []struct {
		method, path string
	}{
		{http.MethodGet, "/healthz"},
		{http.MethodPost, "/pull"},
	} {
		req, err := http.NewRequest(test.method, server.URL+test.path, strings.NewReader(`{"worker_id":"worker-a"}`))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			t.Errorf("%s %s unexpectedly returned 404", test.method, test.path)
		}
	}
}

func (f fakeDBProbe) Ping(context.Context) error { return f.err }

func TestCoordinatorHealthAndPull(t *testing.T) {
	handler, err := NewCoordinatorHandler("coord-a", fakeDBProbe{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	response, err := PullOnce(context.Background(), server.Client(), server.URL, "worker-a")
	if err != nil {
		t.Fatal(err)
	}
	if response.CoordinatorID != "coord-a" || response.WorkerID != "worker-a" || len(response.WorkItems) != 0 {
		t.Fatalf("unexpected pull response: %#v", response)
	}
	resp, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status=%d, want 200", resp.StatusCode)
	}
}

func TestCoordinatorFailsHealthClosedOnDatabaseError(t *testing.T) {
	handler, err := NewCoordinatorHandler("coord-a", fakeDBProbe{err: errors.New("offline")})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health status=%d, want 503", resp.StatusCode)
	}
}

func TestPullOnceRejectsInvalidURLs(t *testing.T) {
	for _, value := range []string{"https://127.0.0.1:1", "http://example.test", "http://user:pass@127.0.0.1:80", "http://127.0.0.1:80/path", `http://localhost:80\\@example.test`, "http://localhost:99999", "http://localhost/%2f"} {
		t.Run(value, func(t *testing.T) {
			if _, err := PullOnce(context.Background(), http.DefaultClient, value, "worker"); !errors.Is(err, ErrInvalidCoordinatorURL) {
				t.Fatalf("PullOnce error=%v, want ErrInvalidCoordinatorURL", err)
			}
		})
	}
}

func TestCoordinatorRejectsMalformedPull(t *testing.T) {
	handler, err := NewCoordinatorHandler("coord-a", fakeDBProbe{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	for _, body := range []string{"{}", `{"worker_id":"worker","extra":true}`, `{"worker_id":"worker"} {}`} {
		req, err := http.NewRequest(http.MethodPost, server.URL+"/pull", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("body %q: status=%d, want 400", body, resp.StatusCode)
		}
	}
}
