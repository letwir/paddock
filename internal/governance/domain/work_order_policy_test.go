package domain

import "testing"

func TestWorkOrderPolicyAxesAndCanonicalDigest(t *testing.T) {
	p := WorkOrderPolicy{Mode: OfflineCompute, Checkpoint: Checkpointable, ExternalActions: []string{"zeta", "alpha"}}
	q := WorkOrderPolicy{Mode: OfflineCompute, Checkpoint: Checkpointable, ExternalActions: []string{"alpha", "zeta"}}
	got, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"checkpointability":"CHECKPOINTABLE","external_actions":["alpha","zeta"],"low_risk_actions":[],"mode":"OFFLINE_COMPUTE"}`
	if string(got) != want {
		t.Fatalf("unexpected JCS:\n got %s\nwant %s", got, want)
	}
	d1, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := q.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 || len(d1) != 64 {
		t.Fatalf("noncanonical digest: %q %q", d1, d2)
	}
}

func TestWorkOrderPolicyLowRiskSubsetAndDigestBinding(t *testing.T) {
	p := WorkOrderPolicy{Mode: OnlineRequired, Checkpoint: NotCheckpointable,
		ExternalActions: []string{"read", "write"}, LowRiskActions: []string{"read"}}
	q := WorkOrderPolicy{Mode: OnlineRequired, Checkpoint: NotCheckpointable,
		ExternalActions: []string{"write", "read"}, LowRiskActions: []string{"read"}}
	r := WorkOrderPolicy{Mode: OnlineRequired, Checkpoint: NotCheckpointable,
		ExternalActions: []string{"read", "write"}, LowRiskActions: []string{"write"}}
	for _, policy := range []WorkOrderPolicy{p, q, r} {
		if err := policy.Validate(); err != nil {
			t.Fatalf("valid low-risk subset rejected: %v", err)
		}
	}
	d1, err := p.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := q.Digest()
	if err != nil {
		t.Fatal(err)
	}
	d3, err := r.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatalf("list order changed digest: %q != %q", d1, d2)
	}
	if d1 == d3 {
		t.Fatal("changing low-risk classification did not change digest")
	}
}

func TestWorkOrderPolicyJCSUTF16ActionOrderAndEscaping(t *testing.T) {
	// UTF-8 byte order places U+E000 before U+10000; UTF-16 JCS order is
	// the reverse because U+10000 begins with surrogate D800.
	p := WorkOrderPolicy{Mode: OnlineRequired, Checkpoint: NotCheckpointable,
		ExternalActions: []string{"\ue000", "\U00010000"}, LowRiskActions: []string{"\ue000", "\U00010000"}}
	got, err := p.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"checkpointability":"NOT_CHECKPOINTABLE","external_actions":["𐀀",""],"low_risk_actions":["𐀀",""],"mode":"ONLINE_REQUIRED"}`
	if string(got) != want {
		t.Fatalf("JCS UTF-16 ordering mismatch:\n got %s\nwant %s", got, want)
	}

	escaped := WorkOrderPolicy{Mode: OfflineCompute, Checkpoint: Checkpointable,
		ExternalActions: []string{"q\"\\\x01\n\t雪"}, LowRiskActions: []string{"q\"\\\x01\n\t雪"}}
	got, err = escaped.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want = `{"checkpointability":"CHECKPOINTABLE","external_actions":["q\"\\\u0001\n\t雪"],"low_risk_actions":["q\"\\\u0001\n\t雪"],"mode":"OFFLINE_COMPUTE"}`
	if string(got) != want {
		t.Fatalf("JCS escaping/Unicode mismatch:\n got %s\nwant %s", got, want)
	}
}

func TestWorkOrderPolicyRejectsInvalidAxesAndActions(t *testing.T) {
	cases := []WorkOrderPolicy{
		{Mode: "OFFLINE", Checkpoint: Checkpointable},
		{Mode: OnlineRequired, Checkpoint: "MAYBE"},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"*"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"%"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read", "read"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{" "}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{string([]byte{0xff})}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read"}, LowRiskActions: []string{"write"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read"}, LowRiskActions: []string{"read", "read"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read"}, LowRiskActions: []string{" read"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read"}, LowRiskActions: []string{"*"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read"}, LowRiskActions: []string{"%"}},
		{Mode: OnlineRequired, Checkpoint: Checkpointable, ExternalActions: []string{"read"}, LowRiskActions: []string{string([]byte{0xff})}},
	}
	for _, p := range cases {
		if p.Validate() == nil {
			t.Errorf("accepted invalid policy: %+v", p)
		}
	}
	p := WorkOrderPolicy{Mode: OnlineRequired, Checkpoint: NotCheckpointable}
	if err := p.Validate(); err != nil {
		t.Fatalf("valid online policy rejected: %v", err)
	}
}
