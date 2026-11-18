package contribution

import (
	storage "github.com/StuHelper/stuhelper-storage"
	"testing"
	"time"
)

func TestVerifiedUsageRetainsFractionalSamples(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	until := start.Add(time.Hour)
	r := Record{View: View{State: "active", DesiredState: "active", Conditions: Conditions{Until: until}, Observation: &Observation{ObservedAt: start, Authorized: true, AuthorizationExpiresAt: until, QuotaExpiresAt: until, UsedBytes: 3600, AvailableBytes: 3600}}}
	for n := 1; n <= 2; n++ {
		observed := start.Add(time.Duration(n) * 1500 * time.Millisecond)
		accumulateVerifiedUsage(&r, storage.ContributionSnapshot{State: "active", ObservedAt: observed, Authorized: true, AuthorizationExpiresAt: until, QuotaExpiresAt: until, UsedBytes: 3600, AvailableBytes: 3600}, 10)
		r.View.Observation.ObservedAt = observed
	}
	if r.VerifiedActiveSeconds != 3 || r.VerifiedUsedByteHours != 3 || r.VerifiedAvailableByteHours != 3 {
		t.Fatal(r)
	}
}
