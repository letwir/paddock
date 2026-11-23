package verification

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/letwir/paddock/internal/canonical"
)

const (
	CIReceiptSchema = "paddock.ci-receipt/1"
	CIReceiptDomain = "paddock.ci-receipt"
)

type RunnerKind string

const (
	RunnerCI      RunnerKind = "CI_RUNNER"
	RunnerTrusted RunnerKind = "TRUSTED_RUNNER"
	RunnerWorker  RunnerKind = "WORKER"
)

var (
	ErrReceiptInvalid           = errors.New("invalid verification receipt")
	ErrReceiptTampered          = errors.New("verification receipt signature or digest invalid")
	ErrWorkerSelfAttestDenied   = errors.New("worker cannot attest PASS or trigger DONE transition")
	ErrMissingIndependentReview = errors.New("distinct independent review required for DONE transition")
	ErrChecksFailed             = errors.New("runner checks or fixtures did not pass")
)

type TargetDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type FixtureResult struct {
	Name     string `json:"name"`
	ExitCode int    `json:"exit_code"`
	Passed   bool   `json:"passed"`
}

type RunnerMetadata struct {
	Kind        RunnerKind `json:"kind"`
	Identity    string     `json:"identity"`
	RunID       string     `json:"run_id"`
	Workflow    string     `json:"workflow,omitempty"`
	Attestation string     `json:"attestation"`
}

type RunnerObservations struct {
	ExitCode     int             `json:"exit_code"`
	GoVersion    string          `json:"go_version"`
	GitHead      string          `json:"git_head"`
	GitTree      string          `json:"git_tree"`
	DirtyDiffSHA string          `json:"dirty_diff_sha256"`
	UntrackedSHA string          `json:"untracked_files_sha256"`
	Targets      []TargetDigest  `json:"targets"`
	Fixtures     []FixtureResult `json:"fixtures"`
}

type TestExecutionSummary struct {
	Passed  bool   `json:"passed"`
	Summary string `json:"summary"`
}

type IndependentReviewRecord struct {
	Present                 bool   `json:"present"`
	ReviewerID              string `json:"reviewer_id"`
	Model                   string `json:"model"`
	Verdict                 string `json:"verdict"`
	Scope                   string `json:"scope"`
	DistinctFromImplementer bool   `json:"distinct_from_implementer"`
}

type ReceiptSignature struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	ValueHex  string `json:"value_hex"`
}

type VerificationReceipt struct {
	SchemaVersion     string                  `json:"schema_version"`
	Domain            string                  `json:"domain"`
	IssueID           string                  `json:"issue_id"`
	Runner            RunnerMetadata          `json:"runner"`
	Observations      RunnerObservations      `json:"observations"`
	TestExecution     TestExecutionSummary    `json:"test_execution"`
	IndependentReview IndependentReviewRecord `json:"independent_review"`
	TimeFinishUTC     string                  `json:"time_finish_utc"`
	Signature         ReceiptSignature        `json:"signature"`
}

func isHexDigest64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func isGitObjectID(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func validateReceiptPayload(r VerificationReceipt) error {
	if r.SchemaVersion != CIReceiptSchema || r.Domain != CIReceiptDomain {
		return fmt.Errorf("%w: invalid schema or domain", ErrReceiptInvalid)
	}
	if strings.TrimSpace(r.IssueID) == "" || strings.TrimSpace(r.Runner.Identity) == "" || strings.TrimSpace(r.TimeFinishUTC) == "" {
		return fmt.Errorf("%w: missing required metadata", ErrReceiptInvalid)
	}
	if strings.TrimSpace(r.Observations.GoVersion) == "" ||
		!isGitObjectID(r.Observations.GitHead) ||
		!isGitObjectID(r.Observations.GitTree) ||
		!isHexDigest64(r.Observations.DirtyDiffSHA) ||
		!isHexDigest64(r.Observations.UntrackedSHA) ||
		len(r.Observations.Targets) == 0 ||
		len(r.Observations.Fixtures) == 0 {
		return fmt.Errorf("%w: incomplete runner git/go/target/fixture observations", ErrReceiptInvalid)
	}
	for _, td := range r.Observations.Targets {
		if strings.TrimSpace(td.Path) == "" || !isHexDigest64(td.SHA256) {
			return fmt.Errorf("%w: invalid target digest for %q", ErrReceiptInvalid, td.Path)
		}
	}
	return nil
}

// SigningBytes returns the domain-separated RFC 8785 canonical JSON over all
// receipt fields excluding Signature.
func (r VerificationReceipt) SigningBytes() ([]byte, error) {
	if err := validateReceiptPayload(r); err != nil {
		return nil, err
	}
	unsigned := struct {
		SchemaVersion     string                  `json:"schema_version"`
		Domain            string                  `json:"domain"`
		IssueID           string                  `json:"issue_id"`
		Runner            RunnerMetadata          `json:"runner"`
		Observations      RunnerObservations      `json:"observations"`
		TestExecution     TestExecutionSummary    `json:"test_execution"`
		IndependentReview IndependentReviewRecord `json:"independent_review"`
		TimeFinishUTC     string                  `json:"time_finish_utc"`
	}{
		SchemaVersion:     r.SchemaVersion,
		Domain:            r.Domain,
		IssueID:           r.IssueID,
		Runner:            r.Runner,
		Observations:      r.Observations,
		TestExecution:     r.TestExecution,
		IndependentReview: r.IndependentReview,
		TimeFinishUTC:     r.TimeFinishUTC,
	}
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return nil, err
	}
	return canonical.NewJCSCodec().CanonicalizeJSON(raw)
}

func (r VerificationReceipt) Sign(priv ed25519.PrivateKey, keyID string) (VerificationReceipt, error) {
	if len(priv) != ed25519.PrivateKeySize || strings.TrimSpace(keyID) == "" {
		return VerificationReceipt{}, fmt.Errorf("%w: invalid signing key or key_id", ErrReceiptInvalid)
	}
	if r.SchemaVersion == "" {
		r.SchemaVersion = CIReceiptSchema
	}
	if r.Domain == "" {
		r.Domain = CIReceiptDomain
	}
	if r.TimeFinishUTC == "" {
		r.TimeFinishUTC = time.Now().UTC().Format(time.RFC3339)
	}
	signingBytes, err := r.SigningBytes()
	if err != nil {
		return VerificationReceipt{}, err
	}
	sig := ed25519.Sign(priv, signingBytes)
	r.Signature = ReceiptSignature{
		Algorithm: "ed25519",
		KeyID:     keyID,
		ValueHex:  hex.EncodeToString(sig),
	}
	return r, nil
}

func (r VerificationReceipt) VerifySignature(trustedKeyID string, trustedPub ed25519.PublicKey) error {
	if len(trustedPub) != ed25519.PublicKeySize || strings.TrimSpace(trustedKeyID) == "" {
		return fmt.Errorf("%w: trusted public key required", ErrReceiptTampered)
	}
	if r.Signature.Algorithm != "ed25519" || r.Signature.KeyID != trustedKeyID {
		return fmt.Errorf("%w: unexpected signature algorithm or key_id", ErrReceiptTampered)
	}
	sigBytes, err := hex.DecodeString(r.Signature.ValueHex)
	if err != nil || len(sigBytes) != ed25519.SignatureSize {
		return fmt.Errorf("%w: malformed signature encoding", ErrReceiptTampered)
	}
	signingBytes, err := r.SigningBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(trustedPub, signingBytes, sigBytes) {
		return fmt.Errorf("%w: ed25519 signature verification failed", ErrReceiptTampered)
	}
	return nil
}

// ValidateDoneTransition enforces the [*] -> [x] gate:
//   - Implementer identity is mandatory (cannot bypass identity separation)
//   - Worker cannot self-attest PASS or act as Runner/Reviewer
//   - Signature and observed git/go/target/dirty/untracked digests must verify
//   - ExitCode == 0, TestExecution.Passed, and all observed Fixtures passed
//   - IndependentReview must be present, distinct from implementer, and "No findings."
func ValidateDoneTransition(r VerificationReceipt, implementerWorkerID, trustedKeyID string, trustedPub ed25519.PublicKey) error {
	implementerWorkerID = strings.TrimSpace(implementerWorkerID)
	if implementerWorkerID == "" {
		return fmt.Errorf("%w: non-empty implementer identity is required", ErrWorkerSelfAttestDenied)
	}
	if r.Runner.Kind == RunnerWorker || (r.Runner.Kind != RunnerCI && r.Runner.Kind != RunnerTrusted) {
		return fmt.Errorf("%w: untrusted runner kind %q", ErrWorkerSelfAttestDenied, r.Runner.Kind)
	}
	if strings.TrimSpace(r.Runner.Identity) == implementerWorkerID {
		return fmt.Errorf("%w: runner identity matches implementer worker", ErrWorkerSelfAttestDenied)
	}
	if r.Runner.Kind == RunnerCI && strings.TrimSpace(r.Runner.RunID) == "" {
		return fmt.Errorf("%w: CI receipt requires non-empty run_id", ErrReceiptInvalid)
	}
	if err := r.VerifySignature(trustedKeyID, trustedPub); err != nil {
		return err
	}
	if r.Observations.ExitCode != 0 || !r.TestExecution.Passed || len(r.Observations.Fixtures) == 0 {
		return fmt.Errorf("%w: exit_code=%d passed=%v fixtures=%d", ErrChecksFailed, r.Observations.ExitCode, r.TestExecution.Passed, len(r.Observations.Fixtures))
	}
	for _, fx := range r.Observations.Fixtures {
		if !fx.Passed || fx.ExitCode != 0 {
			return fmt.Errorf("%w: fixture %q failed (exit_code=%d)", ErrChecksFailed, fx.Name, fx.ExitCode)
		}
	}
	reviewerID := strings.TrimSpace(r.IndependentReview.ReviewerID)
	if !r.IndependentReview.Present ||
		!r.IndependentReview.DistinctFromImplementer ||
		reviewerID == "" ||
		reviewerID == implementerWorkerID ||
		reviewerID == strings.TrimSpace(r.Runner.Identity) ||
		r.IndependentReview.Verdict != "No findings." {
		return fmt.Errorf("%w: test success is distinct from required clean independent review", ErrMissingIndependentReview)
	}
	return nil
}

func ComputeFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashUntrackedFiles(repoRoot string) (string, error) {
	cmd := exec.Command("git", "ls-files", "--others", "--exclude-standard", "-z")
	cmd.Dir = repoRoot
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("list untracked files: %w", err)
	}
	var paths []string
	for _, raw := range bytes.Split(out, []byte{0}) {
		if len(raw) > 0 {
			paths = append(paths, filepath.ToSlash(string(raw)))
		}
	}
	sort.Strings(paths)
	return hashUntrackedPathList(repoRoot, paths)
}

func hashUntrackedDescriptor(h io.Writer, rel, kind string, size int64, body io.Reader, linkTarget string) error {
	switch kind {
	case "file":
		if _, err := fmt.Fprintf(h, "%s\x00file\x00%d\x00", rel, size); err != nil {
			return err
		}
		if body != nil {
			if _, err := io.Copy(h, body); err != nil {
				return err
			}
		}
		_, err := h.Write([]byte{0})
		return err
	case "symlink":
		_, err := fmt.Fprintf(h, "%s\x00symlink\x00%d\x00%s\x00", rel, size, filepath.ToSlash(linkTarget))
		return err
	default:
		return fmt.Errorf("%w: unsupported untracked entry kind %q", ErrReceiptInvalid, kind)
	}
}

func hashUntrackedPathList(repoRoot string, paths []string) (string, error) {
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	h := sha256.New()
	for _, rel := range sorted {
		abs := filepath.Join(repoRoot, filepath.FromSlash(rel))
		info, err := os.Lstat(abs)
		if err != nil {
			return "", fmt.Errorf("stat untracked %q: %w", rel, err)
		}
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(abs)
			if err != nil {
				return "", fmt.Errorf("readlink untracked %q: %w", rel, err)
			}
			if err := hashUntrackedDescriptor(h, rel, "symlink", int64(len(target)), nil, target); err != nil {
				return "", err
			}
		case info.Mode().IsRegular():
			f, err := os.Open(abs)
			if err != nil {
				return "", fmt.Errorf("read untracked %q: %w", rel, err)
			}
			err = hashUntrackedDescriptor(h, rel, "file", info.Size(), f, "")
			closeErr := f.Close()
			if err != nil {
				return "", err
			}
			if closeErr != nil {
				return "", closeErr
			}
		default:
			return "", fmt.Errorf("%w: unsupported untracked file mode %v for %q", ErrReceiptInvalid, info.Mode(), rel)
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type CheckCommand struct {
	Name string
	Args []string
}

// RunAndObserve executes the supplied check commands directly from the Runner,
// capturing real exit codes alongside go version, git HEAD, git tree, dirty diff
// SHA-256, untracked-file tree SHA-256, and target SHA-256 digests.
func RunAndObserve(repoRoot string, targetPaths []string, checks []CheckCommand) (RunnerObservations, error) {
	if len(checks) == 0 {
		return RunnerObservations{}, fmt.Errorf("%w: at least one check command is required", ErrChecksFailed)
	}
	goVerOut, err := exec.Command("go", "version").Output()
	if err != nil {
		return RunnerObservations{}, fmt.Errorf("observe go version: %w", err)
	}
	headCmd := exec.Command("git", "rev-parse", "HEAD")
	headCmd.Dir = repoRoot
	headOut, err := headCmd.Output()
	if err != nil {
		return RunnerObservations{}, fmt.Errorf("observe git head: %w", err)
	}
	treeCmd := exec.Command("git", "rev-parse", "HEAD^{tree}")
	treeCmd.Dir = repoRoot
	treeOut, err := treeCmd.Output()
	if err != nil {
		return RunnerObservations{}, fmt.Errorf("observe git tree: %w", err)
	}
	diffCmd := exec.Command("git", "diff", "HEAD")
	diffCmd.Dir = repoRoot
	diffOut, err := diffCmd.Output()
	if err != nil {
		return RunnerObservations{}, fmt.Errorf("observe git diff: %w", err)
	}
	diffSum := sha256.Sum256(diffOut)
	untrackedSum, err := hashUntrackedFiles(repoRoot)
	if err != nil {
		return RunnerObservations{}, err
	}

	targets := make([]TargetDigest, 0, len(targetPaths))
	for _, rel := range targetPaths {
		cleanRel := filepath.ToSlash(strings.TrimSpace(rel))
		if cleanRel == "" {
			continue
		}
		sum, err := ComputeFileSHA256(filepath.Join(repoRoot, filepath.FromSlash(cleanRel)))
		if err != nil {
			return RunnerObservations{}, fmt.Errorf("hash target %q: %w", cleanRel, err)
		}
		targets = append(targets, TargetDigest{Path: cleanRel, SHA256: sum})
	}
	if len(targets) == 0 {
		return RunnerObservations{}, fmt.Errorf("%w: at least one target file is required", ErrReceiptInvalid)
	}

	fixtures := make([]FixtureResult, 0, len(checks))
	overallExit := 0
	for _, chk := range checks {
		if len(chk.Args) == 0 || strings.TrimSpace(chk.Name) == "" {
			return RunnerObservations{}, fmt.Errorf("%w: invalid check command", ErrChecksFailed)
		}
		c := exec.Command(chk.Args[0], chk.Args[1:]...)
		c.Dir = repoRoot
		runErr := c.Run()
		code := 0
		if runErr != nil {
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				code = exitErr.ExitCode()
			} else {
				code = 1
			}
			if overallExit == 0 {
				overallExit = code
			}
		}
		fixtures = append(fixtures, FixtureResult{
			Name:     chk.Name,
			ExitCode: code,
			Passed:   code == 0,
		})
	}

	return RunnerObservations{
		ExitCode:     overallExit,
		GoVersion:    strings.TrimSpace(string(goVerOut)),
		GitHead:      strings.TrimSpace(string(headOut)),
		GitTree:      strings.TrimSpace(string(treeOut)),
		DirtyDiffSHA: hex.EncodeToString(diffSum[:]),
		UntrackedSHA: untrackedSum,
		Targets:      targets,
		Fixtures:     fixtures,
	}, nil
}
