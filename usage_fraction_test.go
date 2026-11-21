package contribution

import (
	storage "github.com/StuHelper/stuhelper-storage"
	"testing"
	"time"
)

func TestVerifiedUsageRetainsFractionalSamples(t *testing.T) {
	start := time.Unix(100, 0).UTC()
	until := start.Add(time.Hour)
	r := Record{SnapshotAt: start, View: View{State: "active", DesiredState: "active", Conditions: Conditions{Until: until}, Observation: &Observation{ObservedAt: &start, Authorized: true, AuthorizationExpiresAt: until, QuotaExpiresAt: until, UsedBytes: 3600, AvailableBytes: 3600}}}
	for n := 1; n <= 2; n++ {
		observed := start.Add(time.Duration(n) * 1500 * time.Millisecond)
		accumulateVerifiedUsage(&r, storage.ContributionSnapshot{State: "active", ObservedAt: &start, SnapshotAt: observed, Authorized: true, AuthorizationExpiresAt: until, QuotaExpiresAt: until, UsedBytes: 3600, AvailableBytes: 3600}, 10)
		r.SnapshotAt = observed
	}
	if r.VerifiedActiveSeconds != 3 || r.VerifiedUsedByteHours != 3 || r.VerifiedAvailableByteHours != 3 {
		t.Fatal(r)
	}
}

func TestLegacyPollTimestampIsNotReportedAsProviderReadTime(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	until := now.Add(time.Hour)
	s := Service{cfg: Config{Clock: func() time.Time { return now }, Policy: Policy{ObservationMaxAgeSeconds: 120}}}
	r := Record{View: View{State: "active", DesiredState: "active", Conditions: Conditions{Until: until},
		Observation: &Observation{ObservedAt: &now, Authorized: true, AuthorizationExpiresAt: until, QuotaExpiresAt: until, AvailableBytes: 1024}}}
	out := s.view(r)
	if !s.observationCurrent(r) || out.Observation.ObservedAt != nil || out.Observation.AvailableBytes != 1024 {
		t.Fatal("legacy poll time is not usable as a provider sample timestamp")
	}
}
