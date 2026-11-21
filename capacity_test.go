package contribution_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
)

func TestProviderCapacityAdmissionAndPrivacy(t *testing.T) {
	h := newFixture(t)
	now := h.clock.Now()
	_, err := h.store.Register(h.ctx, system, "register-capacity", storage.Instance{
		ID: "one", Adapter: "fixture", Ownership: "contributor", OwnerDomain: contribution.OwnerDomain(user),
		CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-one", State: "paused",
		Authorized: true, Limit: 1 << 20, SafetyMargin: 4096, ExpiresAt: now.Add(2 * time.Hour),
	})
	must(t, err)
	handler, err := httpapi.New(h.s, tokenRoleAuth{})
	must(t, err)
	server := httptest.NewServer(handler)
	defer server.Close()
	newClient := func(identity string) *sdk.ClientWithResponses {
		client, err := sdk.NewClientWithResponses(server.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
			r.Header.Set("Authorization", "Bearer "+identity)
			return nil
		}))
		must(t, err)
		return client
	}
	ownerClient, operatorClient := newClient("fixture"), newClient("operator")
	otherOptions, err := operatorClient.ListContributionOptionsWithResponse(h.ctx, nil)
	must(t, err)
	if otherOptions.StatusCode() != 403 || strings.Contains(string(otherOptions.Body), "provider_capacity") {
		t.Fatal("other user accessed owner options")
	}
	options, err := ownerClient.ListContributionOptionsWithResponse(h.ctx, nil)
	must(t, err)
	if options.JSON200 == nil || len(options.JSON200.Items) != 1 {
		t.Fatal("missing owned candidate")
	}
	candidate := options.JSON200.Items[0]
	assertProviderBytes(t, candidate.ProviderCapacity, 2<<20, 1<<20, 1<<20, now)
	maxWithReserve := int64(1<<20 - 4096 - 1024)
	if candidate.SafetyMarginBytes != 4096 || candidate.MaxContributableBytes == nil || *candidate.MaxContributableBytes != maxWithReserve+1024 {
		t.Fatal("candidate did not report the ceiling at zero personal reserve")
	}
	data := sdk.CreateRequest{
		InstanceId: "one", Conditions: sdk.Conditions{LimitBytes: maxWithReserve + 1, PersonalReserve: 1024, Until: now.Add(time.Hour)},
		Consent: sdk.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	}
	params := &sdk.CreateContributionParams{IdempotencyKey: "capacity-create"}
	response, err := ownerClient.CreateContributionWithResponse(h.ctx, params, data)
	must(t, err)
	if response.JSON400 == nil || response.JSON400.DetailCode == nil || *response.JSON400.DetailCode != sdk.LimitExceedsProviderCapacity {
		t.Fatalf("over-limit submission returned %d", response.StatusCode())
	}
	var count int
	must(t, h.admin.QueryRow("SELECT (SELECT count(*) FROM contribution.contributions) + (SELECT count(*) FROM contribution.jobs) + (SELECT count(*) FROM contribution.outbox) + (SELECT count(*) FROM contribution.replays)").Scan(&count))
	if count != 0 {
		t.Fatal("rejected create wrote contribution state")
	}
	data.Conditions.LimitBytes = maxWithReserve
	h.clock.Add(5 * time.Minute)
	options, err = ownerClient.ListContributionOptionsWithResponse(h.ctx, nil)
	must(t, err)
	if options.JSON200 == nil || len(options.JSON200.Items) != 1 {
		t.Fatal("expired quota hid the candidate")
	}
	candidate = options.JSON200.Items[0]
	if string(candidate.ProviderCapacity.Status) != "expired" || candidate.ProviderCapacity.RemainingBytes != nil || candidate.MaxContributableBytes != nil ||
		candidate.ProviderCapacity.ObservedAt == nil || !candidate.ProviderCapacity.ObservedAt.Equal(now) {
		t.Fatal("expired candidate returned an actionable limit or dropped the last read time")
	}
	response, err = ownerClient.CreateContributionWithResponse(h.ctx, params, data)
	must(t, err)
	if response.JSON409 == nil || response.JSON409.DetailCode == nil || *response.JSON409.DetailCode != sdk.ProviderCapacityUnavailable {
		t.Fatalf("expired submission returned %d", response.StatusCode())
	}
	must(t, h.store.RefreshInstance(h.ctx, system, "one"))
	response, err = ownerClient.CreateContributionWithResponse(h.ctx, params, data)
	must(t, err)
	if response.JSON202 == nil || strings.Contains(string(response.Body), "provider_capacity") {
		t.Fatal("create at the exact limit was rejected or response exposed raw quota")
	}
	id := response.JSON202.Id
	h.run(t)
	owner, err := ownerClient.GetContributionWithResponse(h.ctx, id)
	must(t, err)
	if owner.JSON200 == nil {
		t.Fatal("owner detail missing")
	}
	assertProviderBytes(t, owner.JSON200.ProviderCapacity, 2<<20, 1<<20, 1<<20, h.clock.Now())
	list, err := ownerClient.ListContributionsWithResponse(h.ctx, nil)
	must(t, err)
	if list.JSON200 == nil || len(list.JSON200.Items) != 1 {
		t.Fatal("owner list missing")
	}
	assertProviderBytes(t, list.JSON200.Items[0].ProviderCapacity, 2<<20, 1<<20, 1<<20, h.clock.Now())
	other, err := operatorClient.GetContributionWithResponse(h.ctx, id)
	must(t, err)
	if other.StatusCode() != 403 || strings.Contains(string(other.Body), "provider_capacity") {
		t.Fatal("other user accessed owner detail")
	}
	h.policy.deny("contributions.read", true)
	restricted, err := ownerClient.GetContributionWithResponse(h.ctx, id)
	must(t, err)
	h.policy.deny("contributions.read", false)
	if restricted.StatusCode() != 403 || strings.Contains(string(restricted.Body), "provider_capacity") {
		t.Fatal("revoked read permission still allowed owner detail")
	}
	operations, err := operatorClient.ListContributionOperationsWithResponse(h.ctx, nil)
	must(t, err)
	stats, err := operatorClient.GetContributionStatisticsWithResponse(h.ctx)
	must(t, err)
	if operations.JSON200 == nil || len(operations.JSON200.Items) != 1 || stats.JSON200 == nil ||
		strings.Contains(string(operations.Body), "provider_capacity") || strings.Contains(string(stats.Body), "provider_capacity") {
		t.Fatal("unexpected operator/public response or provider quota disclosure")
	}
	must(t, h.admin.QueryRow(`SELECT count(*) FROM (
		SELECT data FROM contribution.contributions
		UNION ALL SELECT data FROM contribution.replays
		UNION ALL SELECT data FROM contribution.outbox
		UNION ALL SELECT data FROM contribution.audit
	) AS saved WHERE data::text LIKE '%"provider_capacity"%'`).Scan(&count))
	if count != 0 {
		t.Fatal("raw provider quota escaped the owner projection")
	}
}

func assertProviderBytes(t *testing.T, p sdk.ProviderCapacity, total, used, remaining int64, at time.Time) {
	t.Helper()
	if string(p.Status) != "available" || p.TotalBytes == nil || *p.TotalBytes != total ||
		p.UsedBytes == nil || *p.UsedBytes != used || p.RemainingBytes == nil || *p.RemainingBytes != remaining ||
		p.ObservedAt == nil || !p.ObservedAt.Equal(at) {
		t.Fatal("incorrect provider quota projection", p)
	}
}

func TestProviderCapacityFailedRefreshExpiryAndRecovery(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.run(t)
	firstRead := h.clock.Now()
	h.clock.Add(time.Minute)
	h.provider.mu.Lock()
	h.provider.verifyErr = storage.ErrUnavailable
	h.provider.mu.Unlock()
	if err := h.store.RefreshInstance(h.ctx, system, "one"); !errors.Is(err, storage.ErrUnavailable) {
		t.Fatalf("wrong refresh error: %v", err)
	}
	check := func(remaining int64) {
		t.Helper()
		view, err := h.s.Get(h.ctx, user, v.ID)
		must(t, err)
		p := view.ProviderCapacity
		if view.Reason != "capacity_read_failed" || p.Status != storage.CapacityReadFailed ||
			p.TotalBytes != nil || p.UsedBytes != nil || p.RemainingBytes != nil || p.ObservedAt == nil || !p.ObservedAt.Equal(firstRead) {
			t.Fatal("refresh failure did not preserve the last successful read time and hide raw bytes")
		}
		if view.Observation == nil || view.Observation.ObservedAt == nil || !view.Observation.ObservedAt.Equal(firstRead) || view.Observation.AvailableBytes != remaining {
			t.Fatalf("wrong contribution availability after refresh failure: %+v", view.Observation)
		}
	}
	check(1024)
	h.run(t)
	h.clock.Add(4 * time.Minute)
	h.run(t)
	check(0)
	stats, err := h.s.Statistics(h.ctx)
	must(t, err)
	if stats.AvailableBytes != 0 {
		t.Fatal("expired capacity reached public availability")
	}
	h.provider.mu.Lock()
	h.provider.verifyErr = nil
	h.provider.quota = storage.ProviderQuotaSample{TotalBytes: 500, UsedBytes: 150}
	h.provider.mu.Unlock()
	h.clock.Add(time.Minute)
	must(t, h.store.RefreshInstance(h.ctx, system, "one"))
	view, err := h.s.Get(h.ctx, user, v.ID)
	must(t, err)
	if view.Reason != "" || view.ProviderCapacity.Status != storage.CapacityAvailable ||
		view.Observation == nil || view.Observation.AvailableBytes != 250 ||
		view.Observation.ObservedAt == nil || !view.Observation.ObservedAt.Equal(h.clock.Now()) {
		t.Fatal("fresh provider result did not restore availability", view)
	}
	h.run(t)
	stats, err = h.s.Statistics(h.ctx)
	must(t, err)
	if stats.AvailableBytes != 250 {
		t.Fatal("statistics did not recalculate after quota recovery", stats)
	}
}

func TestContributionExpansionRejectsInvalidCapacityBeforeRecording(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.run(t)
	request := contribution.CommandRequest{
		Revision: v.Revision, Action: "configure",
		Conditions: &contribution.Conditions{LimitBytes: 1 << 20, PersonalReserve: 100, Until: v.Conditions.Until},
	}
	assertRejected := func(base error, detailCode string) {
		t.Helper()
		_, err := h.s.Command(h.ctx, user, v.ID, "growth", request)
		var detail *contribution.DetailError
		if !errors.Is(err, base) || !errors.As(err, &detail) || detail.DetailCode != detailCode {
			t.Fatalf("expansion returned %v, expected %s", err, detailCode)
		}
		current := h.get(t, v.ID)
		var records, jobs, events, replays int
		must(t, h.admin.QueryRow(`SELECT (SELECT count(*) FROM contribution.contributions), (SELECT count(*) FROM contribution.jobs),
			(SELECT count(*) FROM contribution.outbox), (SELECT count(*) FROM contribution.replays)`).Scan(&records, &jobs, &events, &replays))
		if current.Revision != v.Revision || current.Conditions != v.Conditions || records != 1 || jobs != 1 || events != 2 || replays != 1 {
			t.Fatal("rejected expansion changed durable state")
		}
	}
	assertRejected(contribution.ErrInput, "limit_exceeds_provider_capacity")
	h.clock.Add(5 * time.Minute)
	assertRejected(contribution.ErrConflict, "provider_capacity_unavailable")
	request.Conditions.LimitBytes = 512
	shrunk, err := h.s.Command(h.ctx, user, v.ID, "shrink", request)
	must(t, err)
	h.run(t)
	if current := h.get(t, v.ID); current.AppliedRevision != shrunk.Revision || current.Conditions.LimitBytes != 512 {
		t.Fatal("expired quota prevented a smaller claim")
	}
}

func TestProviderQuotaDropBeforeApplyDoesNotOpenWrites(t *testing.T) {
	h := newFixture(t)
	v := h.create(t, "one")
	h.provider.mu.Lock()
	h.provider.quota = storage.ProviderQuotaSample{TotalBytes: 400, UsedBytes: 150}
	h.provider.mu.Unlock()
	must(t, h.store.RefreshInstance(h.ctx, system, "one"))
	if err := h.s.RunOne(h.ctx, "worker"); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected quota change to reject activation, got %v", err)
	}
	view := h.get(t, v.ID)
	snapshot, err := h.store.InspectContribution(h.ctx, system, "one", contribution.OwnerDomain(user))
	must(t, err)
	if view.State != "blocked" || view.Reason != "limit_exceeds_provider_capacity" ||
		view.AppliedRevision != 0 || snapshot.Control != nil || snapshot.State != "paused" {
		t.Fatal("shrinking provider quota applied the contribution or lost the failure reason")
	}
}
