package verification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func testSignedCIReceipt(t *testing.T, priv ed25519.PrivateKey) VerificationReceipt {
	t.Helper()
	obs := RunnerObservations{
		ExitCode:     0,
		GoVersion:    "go version go1.25.0 linux/amd64",
		GitHead:      "df40050e93ef671afe2e98b0b0360cd65bb00caf",
		GitTree:      "3386dc3d693d6c1c7acff6c625abcbc4c96d6b62",
		DirtyDiffSHA: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		UntrackedSHA: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		Targets: []TargetDigest{
			{Path: "internal/verification/runner.go", SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		},
		Fixtures: []FixtureResult{
			{Name: "go_test_full", ExitCode: 0, Passed: true},
		},
	}
	rec := VerificationReceipt{
		SchemaVersion: CIReceiptSchema,
		Domain:        CIReceiptDomain,
		IssueID:       "PDK-M14-S04",
		Runner: RunnerMetadata{
			Kind:        RunnerCI,
			Identity:    "github-actions",
			RunID:       "123456789",
			Workflow:    "paddock-ci",
			Attestation: "GITHUB_ACTIONS_ARTIFACT",
		},
		Observations: obs,
		TestExecution: TestExecutionSummary{
			Passed:  true,
			Summary: "all suites passed",
		},
		IndependentReview: IndependentReviewRecord{
			Present:                 true,
			ReviewerID:              "pi-gpt-6.1-sol",
			Model:                   "openai/gpt-6.1-sol",
			Verdict:                 "No findings.",
			Scope:                   "internal/verification/runner.go",
			DistinctFromImplementer: true,
		},
		TimeFinishUTC: "2026-11-23T02:00:00Z",
	}
	signed, err := rec.Sign(priv, "ci-key-01")
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	return signed
}

func TestDoneTransitionGateRejectsWorkerTamperingAndMissingReview(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	valid := testSignedCIReceipt(t, priv)
	if err := ValidateDoneTransition(valid, "worker_impl_01", "ci-key-01", pub); err != nil {
		t.Fatalf("valid receipt rejected: %v", err)
	}

	// Empty implementerWorkerID must never bypass identity-separation checks.
	if err := ValidateDoneTransition(valid, "", "ci-key-01", pub); !errors.Is(err, ErrWorkerSelfAttestDenied) {
		t.Fatalf("expected ErrWorkerSelfAttestDenied on empty implementerWorkerID, got %v", err)
	}

	// Worker cannot self-write PASS even with a valid signature.
	workerSelf := valid
	workerSelf.Runner.Kind = RunnerWorker
	workerSelf.Runner.Identity = "worker_impl_01"
	workerSelf, err = workerSelf.Sign(priv, "ci-key-01")
	if err != nil {
		t.Fatalf("resign failed: %v", err)
	}
	if err := ValidateDoneTransition(workerSelf, "worker_impl_01", "ci-key-01", pub); !errors.Is(err, ErrWorkerSelfAttestDenied) {
		t.Fatalf("expected ErrWorkerSelfAttestDenied for worker runner, got %v", err)
	}

	// Tampered receipt body fails signature check.
	tampered := valid
	tampered.Observations.UntrackedSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if err := ValidateDoneTransition(tampered, "worker_impl_01", "ci-key-01", pub); !errors.Is(err, ErrReceiptTampered) {
		t.Fatalf("expected ErrReceiptTampered on tampered UntrackedSHA, got %v", err)
	}

	// Test execution pass WITHOUT independent review must be rejected for [*] -> [x].
	noReview := valid
	noReview.IndependentReview = IndependentReviewRecord{Present: false}
	noReview, err = noReview.Sign(priv, "ci-key-01")
	if err != nil {
		t.Fatalf("resign failed: %v", err)
	}
	if err := ValidateDoneTransition(noReview, "worker_impl_01", "ci-key-01", pub); !errors.Is(err, ErrMissingIndependentReview) {
		t.Fatalf("expected ErrMissingIndependentReview, got %v", err)
	}

	// Reviewer identical to implementer or runner must be rejected.
	selfReview := valid
	selfReview.IndependentReview.ReviewerID = "worker_impl_01"
	selfReview, err = selfReview.Sign(priv, "ci-key-01")
	if err != nil {
		t.Fatalf("resign failed: %v", err)
	}
	if err := ValidateDoneTransition(selfReview, "worker_impl_01", "ci-key-01", pub); !errors.Is(err, ErrMissingIndependentReview) {
		t.Fatalf("expected ErrMissingIndependentReview for self-review, got %v", err)
	}

	// Non-zero exit code fails closed even if TestExecution.Passed claims true.
	failedFixture := valid
	failedFixture.Observations.ExitCode = 1
	failedFixture, err = failedFixture.Sign(priv, "ci-key-01")
	if err != nil {
		t.Fatalf("resign failed: %v", err)
	}
	if err := ValidateDoneTransition(failedFixture, "worker_impl_01", "ci-key-01", pub); !errors.Is(err, ErrChecksFailed) {
		t.Fatalf("expected ErrChecksFailed, got %v", err)
	}
}

func TestUntrackedDescriptorAndSymlinkRetargetingChangesDigest(t *testing.T) {
	hashWith := func(kind string, size int64, body []byte, linkTarget string) string {
		h := sha256.New()
		var r *bytes.Reader
		if body != nil {
			r = bytes.NewReader(body)
		}
		if err := hashUntrackedDescriptor(h, "scripts/hook.sh", kind, size, r, linkTarget); err != nil {
			t.Fatalf("hashUntrackedDescriptor failed: %v", err)
		}
		return hex.EncodeToString(h.Sum(nil))
	}

	// Same-length symlink retargeting (good.sh -> evil.sh) MUST produce distinct digests.
	goodLink := hashWith("symlink", 7, nil, "good.sh")
	evilLink := hashWith("symlink", 7, nil, "evil.sh")
	if goodLink == evilLink {
		t.Fatalf("same-length symlink retargeting yielded identical digest %s", goodLink)
	}
	// Symlink vs regular file with identical target bytes MUST also differ by file kind.
	regFile := hashWith("file", 7, []byte("good.sh"), "")
	if regFile == goodLink {
		t.Fatalf("regular file and symlink yielded identical digest %s", regFile)
	}

	// Also exercise real OS symlinks via hashUntrackedPathList when permitted by host OS.
	tmp := t.TempDir()
	linkPath := filepath.Join(tmp, "hook.sh")
	if err := os.Symlink("good.sh", linkPath); err == nil {
		d1, err := hashUntrackedPathList(tmp, []string{"hook.sh"})
		if err != nil {
			t.Fatalf("hashUntrackedPathList symlink 1 failed: %v", err)
		}
		if err := os.Remove(linkPath); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("evil.sh", linkPath); err != nil {
			t.Fatal(err)
		}
		d2, err := hashUntrackedPathList(tmp, []string{"hook.sh"})
		if err != nil {
			t.Fatalf("hashUntrackedPathList symlink 2 failed: %v", err)
		}
		if d1 == d2 {
			t.Fatalf("OS symlink retargeting yielded identical UntrackedSHA %s", d1)
		}
	}
}
