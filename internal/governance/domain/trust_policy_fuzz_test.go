package domain

import "testing"

func FuzzTrustPolicyParse(f *testing.F) {
	f.Add([]byte(`{"schema_version":"paddock.trust-policy/1","policy_type":"risk_adaptive_threshold_table","rules":[{"risk_tier":"G1","capability":"cap.read","q1_min_independent":2,"q2_min_independent":3,"q3_min_independent":5,"integrity_demote_to":"Q0"}]}`))
	f.Add([]byte(`{"schema_version":"paddock.trust-policy/1","policy_type":"risk_adaptive_threshold_table","unknown":true,"rules":[]}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`{"rules":null}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		pol, err := DecodeTrustPolicy(data)
		if err != nil {
			return
		}
		if len(pol.rules) == 0 {
			t.Fatalf("accepted empty decoded TrustPolicy: %+v", pol)
		}
	})
}
