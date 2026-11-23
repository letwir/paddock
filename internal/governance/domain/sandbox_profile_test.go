package domain

import (
	"errors"
	"testing"
)

func TestSandboxProfileRejectsPRootAndUnverifiedIsolation(t *testing.T) {
	if SandboxPRoot.IsIsolationBoundary() || SandboxNone.IsIsolationBoundary() {
		t.Fatal("PRoot/None must never be classified as security boundaries")
	}

	cases := []struct {
		name    string
		profile SandboxProfile
		worker  WorkerSandboxCapability
		wantErr bool
	}{
		{
			name:    "untrusted code rejected on proot even with flags true",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "termux-1", ObservedKind: SandboxPRoot, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 256, AvailableMemoryMB: 512},
			wantErr: true,
		},
		{
			name:    "untrusted code profile itself cannot choose proot",
			profile: SandboxProfile{RequiredKind: SandboxPRoot, UntrustedCode: true},
			worker:  WorkerSandboxCapability{WorkerID: "termux-1", ObservedKind: SandboxPRoot, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true},
			wantErr: true,
		},
		{
			name:    "unverified probe fails closed",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "w-1", ObservedKind: SandboxMicroVM, ProbeVerified: false, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 256},
			wantErr: true,
		},
		{
			name:    "wasm cannot satisfy microvm requirement",
			profile: SandboxProfile{RequiredKind: SandboxMicroVM, UntrustedCode: true, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "w-1", ObservedKind: SandboxWasmWASI, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 256},
			wantErr: true,
		},
		{
			name:    "missing network enforcement rejected",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, AllowNetwork: false, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "w-1", ObservedKind: SandboxWasmWASI, ProbeVerified: true, EnforcesNoNetwork: false, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 256},
			wantErr: true,
		},
		{
			name:    "missing host FS enforcement rejected",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, AllowWritableHostFS: false, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "w-1", ObservedKind: SandboxWasmWASI, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: false, EnforcedMaxMemoryMB: 256},
			wantErr: true,
		},
		{
			name:    "zero profile MaxMemoryMB fails closed for untrusted code",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, MaxMemoryMB: 0},
			worker:  WorkerSandboxCapability{WorkerID: "vm-1", ObservedKind: SandboxMicroVM, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 256, AvailableMemoryMB: 1024},
			wantErr: true,
		},
		{
			name:    "absent enforced memory limit rejected when profile specifies MaxMemoryMB",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "vm-1", ObservedKind: SandboxMicroVM, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 0, AvailableMemoryMB: 1024},
			wantErr: true,
		},
		{
			name:    "excessive enforced memory limit rejected",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "vm-1", ObservedKind: SandboxMicroVM, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 1024, AvailableMemoryMB: 1024},
			wantErr: true,
		},
		{
			name:    "microvm enforcing exact memory cap on larger host passes",
			profile: SandboxProfile{RequiredKind: SandboxWasmWASI, UntrustedCode: true, MaxMemoryMB: 256},
			worker:  WorkerSandboxCapability{WorkerID: "vm-1", ObservedKind: SandboxMicroVM, ProbeVerified: true, EnforcesNoNetwork: true, EnforcesReadOnlyHostFS: true, EnforcedMaxMemoryMB: 256, AvailableMemoryMB: 1024},
			wantErr: false,
		},
		{
			name:    "trusted non-untrusted profile may run on verified host with explicit allowances",
			profile: SandboxProfile{RequiredKind: SandboxNone, UntrustedCode: false, AllowNetwork: true, AllowWritableHostFS: true},
			worker:  WorkerSandboxCapability{WorkerID: "trusted-1", ObservedKind: SandboxNone, ProbeVerified: true},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := EvaluateSandboxDispatch(tc.profile, tc.worker)
			if tc.wantErr && !errors.Is(err, ErrSandboxRejected) {
				t.Fatalf("expected ErrSandboxRejected, got %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}
