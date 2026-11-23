package domain

import (
	"errors"
	"fmt"
)

var ErrSandboxRejected = errors.New("sandbox isolation capability rejected")

// SandboxKind classifies the runtime isolation boundary enforced by a Worker.
type SandboxKind string

const (
	SandboxNone              SandboxKind = "NONE"
	SandboxPRoot             SandboxKind = "PROOT"
	SandboxWasmWASI          SandboxKind = "WASM_WASI"
	SandboxContainerHardened SandboxKind = "CONTAINER_HARDENED"
	SandboxMicroVM           SandboxKind = "MICROVM"
)

// IsIsolationBoundary reports whether kind provides a real security boundary
// for untrusted code. Termux/userspace PRoot is explicitly NOT an isolation boundary.
func (k SandboxKind) IsIsolationBoundary() bool {
	switch k {
	case SandboxWasmWASI, SandboxContainerHardened, SandboxMicroVM:
		return true
	default:
		return false
	}
}

func (k SandboxKind) strengthRank() int {
	switch k {
	case SandboxNone:
		return 0
	case SandboxPRoot:
		return 0
	case SandboxWasmWASI:
		return 1
	case SandboxContainerHardened:
		return 2
	case SandboxMicroVM:
		return 3
	default:
		return -1
	}
}

func (k SandboxKind) Validate() error {
	if k.strengthRank() < 0 {
		return fmt.Errorf("%w: unknown sandbox kind %q", ErrSandboxRejected, k)
	}
	return nil
}

// SandboxProfile specifies the minimum isolation and maximum resource cap
// requirements for a WorkOrder.
type SandboxProfile struct {
	RequiredKind        SandboxKind
	UntrustedCode       bool
	AllowNetwork        bool
	AllowWritableHostFS bool
	MaxMemoryMB         uint64
}

func (p SandboxProfile) Validate() error {
	if err := p.RequiredKind.Validate(); err != nil {
		return err
	}
	if p.UntrustedCode && !p.RequiredKind.IsIsolationBoundary() {
		return fmt.Errorf("%w: untrusted code profile cannot specify non-isolating kind %q", ErrSandboxRejected, p.RequiredKind)
	}
	if p.UntrustedCode && p.MaxMemoryMB == 0 {
		return fmt.Errorf("%w: untrusted code profile must specify a positive MaxMemoryMB cap", ErrSandboxRejected)
	}
	return nil
}

// WorkerSandboxCapability captures Coordinator-observed sandbox enforcement
// capabilities, separate from untrusted Worker self-claims.
// EnforcedMaxMemoryMB is the hard memory limit enforced on the sandboxed run;
// AvailableMemoryMB is host capacity.
type WorkerSandboxCapability struct {
	WorkerID               string
	ObservedKind           SandboxKind
	ProbeVerified          bool
	EnforcesNoNetwork      bool
	EnforcesReadOnlyHostFS bool
	EnforcedMaxMemoryMB    uint64
	AvailableMemoryMB      uint64
}

// EvaluateSandboxDispatch fails closed whenever a Worker lacks verified
// real isolation matching the SandboxProfile (explicitly rejecting PRoot) or
// fails to enforce the profile's maximum memory cap.
func EvaluateSandboxDispatch(profile SandboxProfile, worker WorkerSandboxCapability) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	if validateID(worker.WorkerID) != nil || worker.ObservedKind.Validate() != nil {
		return fmt.Errorf("%w: malformed worker sandbox capability", ErrSandboxRejected)
	}
	if !worker.ProbeVerified {
		return fmt.Errorf("%w: worker %s sandbox capability is unverified", ErrSandboxRejected, worker.WorkerID)
	}
	if profile.UntrustedCode && !worker.ObservedKind.IsIsolationBoundary() {
		return fmt.Errorf("%w: %s is not a security isolation boundary for untrusted code", ErrSandboxRejected, worker.ObservedKind)
	}
	if worker.ObservedKind.strengthRank() < profile.RequiredKind.strengthRank() {
		return fmt.Errorf("%w: worker sandbox %s below required %s", ErrSandboxRejected, worker.ObservedKind, profile.RequiredKind)
	}
	if !profile.AllowNetwork && !worker.EnforcesNoNetwork {
		return fmt.Errorf("%w: network isolation not enforced", ErrSandboxRejected)
	}
	if !profile.AllowWritableHostFS && !worker.EnforcesReadOnlyHostFS {
		return fmt.Errorf("%w: read-only host filesystem not enforced", ErrSandboxRejected)
	}
	if profile.UntrustedCode || profile.MaxMemoryMB > 0 {
		if worker.EnforcedMaxMemoryMB == 0 || worker.EnforcedMaxMemoryMB > profile.MaxMemoryMB {
			return fmt.Errorf("%w: enforced memory cap %dMB missing or exceeds profile maximum %dMB", ErrSandboxRejected, worker.EnforcedMaxMemoryMB, profile.MaxMemoryMB)
		}
		if worker.AvailableMemoryMB > 0 && worker.AvailableMemoryMB < worker.EnforcedMaxMemoryMB {
			return fmt.Errorf("%w: available memory %dMB below enforced limit %dMB", ErrSandboxRejected, worker.AvailableMemoryMB, worker.EnforcedMaxMemoryMB)
		}
	}
	return nil
}
