package contribution_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRenewalWarningsVersionedEventsAndTraceparent(t *testing.T) {
	h := newFixture(t)
	if h.s.Policy().RenewalNoticeSeconds != 7*86400 {
		t.Fatalf("expected default 7-day renewal notice, got %d", h.s.Policy().RenewalNoticeSeconds)
	}

	cfg := h.cfg
	cfg.Policy.RenewalNoticeSeconds = 120 // 2 minutes
	svc, err := contribution.New(h.repo, h.policy, h.bridge, cfg)
	must(t, err)
	h.s = svc

	now0 := h.clock.Now()
	_, err = h.store.Register(h.ctx, system, "register-one", storage.Instance{
		ID: "one", Adapter: "fixture", AccountDomain: "fixture:one", OwnerDomain: contribution.OwnerDomain(user),
		Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-one",
		State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now0.Add(6 * time.Minute),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now0.Add(6 * time.Minute)}},
	})
	must(t, err)
	qOne := contribution.CreateRequest{
		InstanceID: "one",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 100, Until: now0.Add(4 * time.Minute)},
		Consent:    contribution.Consent{Accepted: true, Version: cfg.Policy.Terms.Version, Digest: cfg.Policy.Terms.Digest},
	}
	qTwo := h.request(t, "two")
	_, err = h.store.Register(h.ctx, system, "register-three", storage.Instance{
		ID: "three", Adapter: "fixture", AccountDomain: "fixture:three", OwnerDomain: contribution.OwnerDomain(user),
		Ownership: "contributor", CredentialRef: "fixture", CredentialRevision: 1, Root: "isolated-three",
		State: "paused", Authorized: true, Limit: 1 << 20, ExpiresAt: now0.Add(7 * time.Minute),
		Admissions: []storage.Admission{{Class: "public", Scope: "school", Plaintext: true, ExpiresAt: now0.Add(7 * time.Minute)}},
	})
	must(t, err)
	qThree := contribution.CreateRequest{
		InstanceID: "three",
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 100, Until: now0.Add(2 * time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: cfg.Policy.Terms.Version, Digest: cfg.Policy.Terms.Digest},
	}

	const validTrace = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	const zeroTrace = "00-00000000000000000000000000000000-00f067aa0ba902b7-01"

	var currentTrace string
	handler, err := httpapi.New(h.s, fixtureAuth{})
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()
	client, err := sdk.NewClientWithResponses(srv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture")
		if currentTrace != "" {
			r.Header.Set("Traceparent", currentTrace)
		}
		return nil
	}))
	must(t, err)

	b, err := json.Marshal(qOne)
	must(t, err)
	var createInput sdk.CreateRequest
	must(t, json.Unmarshal(b, &createInput))

	currentTrace = validTrace
	created, err := client.CreateContributionWithResponse(h.ctx, &sdk.CreateContributionParams{IdempotencyKey: "create-one"}, createInput)
	must(t, err)
	if created.JSON202 == nil {
		t.Fatalf("create failed: %d %s", created.StatusCode(), string(created.Body))
	}
	idOne := created.JSON202.Id

	h.run(t)
	v := h.get(t, idOne)
	if len(v.Warnings) != 0 {
		t.Fatalf("expected no warnings when 1h > 30m notice window, got %v", v.Warnings)
	}
	_, err = h.s.Sweep(h.ctx, 100, "")
	must(t, err)

	// Enter the 2-minute consent warning window (1m remaining, auth still has 3m).
	h.clock.Add(3 * time.Minute)
	v = h.get(t, idOne)
	if !slices.Equal(v.Warnings, []string{"consent_expiring_soon"}) {
		t.Fatalf("expected consent_expiring_soon warning, got %v", v.Warnings)
	}

	_, err = h.s.Sweep(h.ctx, 100, "")
	must(t, err)
	_, err = h.s.Sweep(h.ctx, 100, "")
	must(t, err)

	events := drainOutbox(t, h)
	expiringCount := 0
	for _, ev := range events {
		if !strings.HasSuffix(ev.Type, ".v1") {
			t.Fatalf("expected versioned event type, got %s", ev.Type)
		}
		if ev.Traceparent != validTrace {
			t.Fatalf("expected propagated traceparent %q on %s, got %q", validTrace, ev.Type, ev.Traceparent)
		}
		if ev.Type == "contribution.expiring_soon.v1" {
			expiringCount++
			if !slices.Equal(ev.Data.Warnings, []string{"consent_expiring_soon"}) {
				t.Fatalf("expected warning payload on expiring_soon, got %+v", ev.Data)
			}
		}
	}
	if expiringCount != 1 {
		t.Fatalf("expected exactly 1 expiring_soon event per renewal cycle, got %d", expiringCount)
	}

	// Renew into a second cycle with an invalid all-zero traceparent header (must not overwrite valid trace or fail).
	currentTrace = zeroTrace
	newCond := v.Conditions
	newCond.Until = h.clock.Now().Add(2 * time.Hour)
	consent := contribution.Consent{Accepted: true, Version: cfg.Policy.Terms.Version, Digest: cfg.Policy.Terms.Digest}
	v, err = h.s.Command(contribution.WithTraceparent(h.ctx, zeroTrace), user, idOne, "renew-cycle-2", contribution.CommandRequest{
		Revision: v.Revision, Action: "renew", Conditions: &newCond, Consent: &consent,
	})
	must(t, err)
	h.run(t)
	v = h.get(t, idOne)
	if len(v.Warnings) != 0 {
		t.Fatalf("expected warnings cleared after renew, got %v", v.Warnings)
	}
	_ = drainOutbox(t, h)

	// Advance 90s (now T0+4m30s): AuthorizationExpiresAt (T0+6m, 90s left) enters 2m warning window while 5m quota remains valid.
	h.clock.Add(90 * time.Second)
	v = h.get(t, idOne)
	if !slices.Equal(v.Warnings, []string{"authorization_expiring_soon"}) {
		t.Fatalf("expected authorization_expiring_soon, got %v", v.Warnings)
	}
	_, err = h.s.Sweep(h.ctx, 100, "")
	must(t, err)
	authWarnEvents := drainOutbox(t, h)
	if len(authWarnEvents) != 1 || authWarnEvents[0].Type != "contribution.expiring_soon.v1" || !slices.Equal(authWarnEvents[0].Data.Warnings, []string{"authorization_expiring_soon"}) {
		t.Fatalf("expected single authorization expiring_soon event, got %+v", authWarnEvents)
	}

	// Clean exit emits contribution.exited.v1.
	v = h.command(t, v, "exit")
	h.run(t)
	exitEvents := drainOutbox(t, h)
	hasExited := false
	for _, ev := range exitEvents {
		if ev.Type == "contribution.exited.v1" && ev.Data.State == "exited" {
			hasExited = true
		}
	}
	if !hasExited {
		t.Fatalf("expected contribution.exited.v1, got %+v", exitEvents)
	}

	// Revoke with remaining replica emits contribution.cleanup_unconfirmed.v1.
	qTwo.Conditions.Until = h.clock.Now().Add(time.Hour)
	two, err := h.s.Create(h.ctx, user, "create-two", qTwo)
	must(t, err)
	h.run(t)
	two = h.get(t, two.ID)
	sum := sha256.Sum256([]byte("z"))
	obj, err := h.store.Create(h.ctx, system, "obj-z", storage.CreateRequest{Size: 1, SHA256: hex.EncodeToString(sum[:]), Protection: storage.Protection{Class: "public", Scope: "school", Public: true}})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj.ID, "write-z", strings.NewReader("z"))
	must(t, err)
	_ = drainOutbox(t, h)
	two = h.command(t, two, "revoke")
	h.run(t)
	revokeEvents := drainOutbox(t, h)
	hasCleanupUnconfirmed := false
	for _, ev := range revokeEvents {
		if ev.Type == "contribution.cleanup_unconfirmed.v1" && ev.Data.Reason == "cleanup_unconfirmed" {
			hasCleanupUnconfirmed = true
		}
	}
	if !hasCleanupUnconfirmed {
		t.Fatalf("expected contribution.cleanup_unconfirmed.v1, got %+v", revokeEvents)
	}

	// Authorization failure during synchronize emits contribution.authorization_required.v1.
	qThree.Conditions.Until = h.clock.Now().Add(2 * time.Hour)
	three, err := h.s.Create(h.ctx, user, "create-three", qThree)
	must(t, err)
	_ = drainOutbox(t, h)
	h.clock.Add(3 * time.Minute) // T0+8m: past T0+7m authorization expiry of instance "three"
	_ = h.s.RunOne(h.ctx, "worker")
	authReqEvents := drainOutbox(t, h)
	if len(authReqEvents) != 1 || authReqEvents[0].Subject != three.ID || authReqEvents[0].Type != "contribution.authorization_required.v1" || authReqEvents[0].Data.Reason != "authorization_required" {
		t.Fatalf("expected contribution.authorization_required.v1, got %+v", authReqEvents)
	}
}

func drainOutbox(t *testing.T, h *fixture) []contribution.Event {
	t.Helper()
	events, err := h.repo.PendingEvents(h.ctx, 100)
	must(t, err)
	for _, ev := range events {
		must(t, h.repo.AcknowledgeEvent(h.ctx, ev.ID))
	}
	return events
}
