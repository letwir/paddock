package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/letwir/paddock/internal/verification"
)

func loadSigningKeyFromEnv(envName string) (ed25519.PrivateKey, error) {
	rawHex := strings.TrimSpace(os.Getenv(envName))
	if rawHex == "" {
		return nil, fmt.Errorf("missing provisioned signing key in %s", envName)
	}
	b, err := hex.DecodeString(rawHex)
	if err != nil {
		return nil, fmt.Errorf("invalid hex in %s", envName)
	}
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(b), nil
	default:
		return nil, fmt.Errorf("unexpected key length %d in %s", len(b), envName)
	}
}

func main() {
	issueID := flag.String("issue", "PDK-M14-S04", "Issue ID for the receipt")
	targetsFlag := flag.String("targets", "internal/verification/runner.go,cmd/verify-runner/main.go", "Comma-separated target paths")
	keyID := flag.String("key-id", "", "Provisioned signing KeyID (required)")
	keyEnv := flag.String("key-env", "PADDOCK_RUNNER_SIGNING_KEY_HEX", "Environment variable holding Ed25519 seed/private key hex")
	outPath := flag.String("out", "ci-verification-receipt.json", "Output JSON path")
	implementerID := flag.String("implementer", "", "Implementer worker ID for distinct review validation")
	reviewFile := flag.String("review-file", "", "Optional path to externally produced IndependentReviewRecord JSON")
	flag.Parse()

	if strings.TrimSpace(*keyID) == "" {
		fmt.Fprintln(os.Stderr, "verify-runner: --key-id is required")
		os.Exit(1)
	}
	priv, err := loadSigningKeyFromEnv(*keyEnv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-runner: %v\n", err)
		os.Exit(1)
	}

	checks := []verification.CheckCommand{
		{Name: "go_test_verification", Args: []string{"go", "test", "./internal/verification", "-count=1"}},
		{Name: "go_vet", Args: []string{"go", "vet", "./internal/verification", "./cmd/verify-runner"}},
	}
	targetPaths := strings.Split(*targetsFlag, ",")
	obs, err := verification.RunAndObserve(".", targetPaths, checks)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-runner: %v\n", err)
		os.Exit(1)
	}

	kind := verification.RunnerTrusted
	identity := "trusted-verification-runner"
	runID := "NONE"
	workflow := ""
	attestation := "PROVISIONED_ED25519_OBSERVATION"
	if ghRun := strings.TrimSpace(os.Getenv("GITHUB_RUN_ID")); ghRun != "" {
		kind = verification.RunnerCI
		identity = "github-actions"
		runID = ghRun
		workflow = strings.TrimSpace(os.Getenv("GITHUB_WORKFLOW"))
		attestation = "GITHUB_ACTIONS_RUN_ARTIFACT"
	}

	// Default is review absent: test execution NEVER fabricates independent review.
	review := verification.IndependentReviewRecord{Present: false}
	if strings.TrimSpace(*reviewFile) != "" {
		rawReview, err := os.ReadFile(*reviewFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "verify-runner: read review file: %v\n", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(rawReview, &review); err != nil {
			fmt.Fprintf(os.Stderr, "verify-runner: invalid review JSON: %v\n", err)
			os.Exit(1)
		}
		review.DistinctFromImplementer = strings.TrimSpace(*implementerID) != "" &&
			strings.TrimSpace(review.ReviewerID) != "" &&
			strings.TrimSpace(review.ReviewerID) != strings.TrimSpace(*implementerID) &&
			strings.TrimSpace(review.ReviewerID) != identity
	}

	rec := verification.VerificationReceipt{
		SchemaVersion: verification.CIReceiptSchema,
		Domain:        verification.CIReceiptDomain,
		IssueID:       *issueID,
		Runner: verification.RunnerMetadata{
			Kind:        kind,
			Identity:    identity,
			RunID:       runID,
			Workflow:    workflow,
			Attestation: attestation,
		},
		Observations: obs,
		TestExecution: verification.TestExecutionSummary{
			Passed:  obs.ExitCode == 0,
			Summary: fmt.Sprintf("executed %d checks directly; overall_exit=%d", len(obs.Fixtures), obs.ExitCode),
		},
		IndependentReview: review,
		TimeFinishUTC:     time.Now().UTC().Format(time.RFC3339),
	}
	signed, err := rec.Sign(priv, strings.TrimSpace(*keyID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-runner: sign failed: %v\n", err)
		os.Exit(1)
	}
	data, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify-runner: marshal failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, append(data, '\n'), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "verify-runner: write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Wrote %s (issue=%s head=%s run_id=%s exit_code=%d review_present=%v)\n",
		*outPath, *issueID, obs.GitHead, runID, obs.ExitCode, review.Present)
}
