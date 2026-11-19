package contribution_test

import (
	"context"
	"errors"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestExitedContributionReleasesActiveQuotaAndReopensSameBinding(t *testing.T) {
	h := newFixture(t)
	cfg := h.cfg
	cfg.Policy.MaxPerOwner = 1
	cfg.MaxContributions = 1
	cfg.ActivationWindow = 2 * time.Minute
	cfg.MaxOwnerActivations = 2
	svc, err := contribution.New(h.repo, h.policy, h.bridge, cfg)
	must(t, err)
	h.s = svc

	first := h.create(t, "one")
	h.run(t)
	first = h.get(t, first.ID)
	if first.State != "active" {
		t.Fatal(first)
	}

	// While active, MaxPerOwner=1 and MaxContributions=1 block a second instance.
	qTwo := h.request(t, "two")
	qThree := h.request(t, "three")
	if _, err := h.s.Create(h.ctx, user, "create-two-blocked", qTwo); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected active quota conflict, got %v", err)
	}

	// Cannot reopen an active contribution.
	reopenConsent := contribution.Consent{Accepted: true, Version: cfg.Policy.Terms.Version, Digest: cfg.Policy.Terms.Digest}
	reopenCond := contribution.Conditions{LimitBytes: 2048, PersonalReserve: 64, Until: h.clock.Now().Add(90 * time.Minute)}
	if _, err := h.s.Command(h.ctx, user, first.ID, "reopen-active", contribution.CommandRequest{Revision: first.Revision, Action: "reopen", Conditions: &reopenCond, Consent: &reopenConsent}); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected conflict reopening active contribution, got %v", err)
	}

	// While exiting (before worker confirms zero-replica exit), active slot stays reserved.
	first = h.command(t, first, "exit")
	if _, err := h.s.Create(h.ctx, user, "create-two-exiting", qTwo); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected exiting record to hold active slot, got %v", err)
	}

	h.run(t)
	first = h.get(t, first.ID)
	if first.State != "exited" {
		t.Fatal(first)
	}

	// Once cleanly exited, active slot is released for another instance, while Create on "one" remains forbidden.
	if _, err := h.s.Create(h.ctx, user, "recreate-one", h.requestForExisting("one")); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected permanent instance binding on Create, got %v", err)
	}
	second, err := h.s.Create(h.ctx, user, "create-two", qTwo)
	must(t, err)
	h.run(t)
	second = h.get(t, second.ID)
	second = h.command(t, second, "exit")
	h.run(t)
	if h.get(t, second.ID).State != "exited" {
		t.Fatal(h.get(t, second.ID))
	}

	// Two activations occurred within ActivationWindow (MaxOwnerActivations=2): reopen is rate-limited until window passes.
	reopenCond.Until = h.clock.Now().Add(90 * time.Minute)
	if _, err := h.s.Command(h.ctx, user, first.ID, "reopen-rate-limited", contribution.CommandRequest{Revision: first.Revision, Action: "reopen", Conditions: &reopenCond, Consent: &reopenConsent}); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected activation window rate limit conflict, got %v", err)
	}

	// Advance past the 2m activation window; instance "one" authorization (2h) remains valid.
	h.clock.Add(3 * time.Minute)
	now := h.clock.Now()

	// Invalid consent or missing conditions on reopen must fail with ErrInput.
	badConsent := reopenConsent
	badConsent.Accepted = false
	reopenCond = contribution.Conditions{LimitBytes: 512, PersonalReserve: 64, Until: now.Add(45 * time.Minute)}
	if _, err := h.s.Command(h.ctx, user, first.ID, "reopen-bad-consent", contribution.CommandRequest{Revision: first.Revision, Action: "reopen", Conditions: &reopenCond, Consent: &badConsent}); !errors.Is(err, contribution.ErrInput) {
		t.Fatalf("expected invalid input for unaccepted consent, got %v", err)
	}

	// Reopen via HTTP generated SDK using sdk.Reopen, preserving permanent ID and advancing revision.
	handler, err := httpapi.New(h.s, fixtureAuth{})
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()
	client, err := sdk.NewClientWithResponses(srv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture")
		return nil
	}))
	must(t, err)

	resp, err := client.CommandContributionWithResponse(h.ctx, first.ID, &sdk.CommandContributionParams{IdempotencyKey: "reopen-one"}, sdk.CommandRequest{
		Revision:   first.Revision,
		Action:     sdk.Reopen,
		Conditions: &sdk.Conditions{LimitBytes: reopenCond.LimitBytes, PersonalReserve: reopenCond.PersonalReserve, Until: reopenCond.Until},
		Consent:    &sdk.Consent{Accepted: true, Version: reopenConsent.Version, Digest: reopenConsent.Digest},
	})
	must(t, err)
	if resp.JSON202 == nil || resp.JSON202.Id != first.ID || resp.JSON202.Revision != first.Revision+1 || string(resp.JSON202.DesiredState) != "active" || string(resp.JSON202.State) != "pending" || resp.JSON202.ExitRequestedAt != nil || resp.JSON202.ExitTargetAt != nil {
		t.Fatalf("unexpected reopen response: status=%d body=%s", resp.StatusCode(), string(resp.Body))
	}

	h.run(t)
	reopened := h.get(t, first.ID)
	if reopened.ID != first.ID || reopened.State != "active" || reopened.AppliedRevision != reopened.Revision || reopened.Conditions.LimitBytes != 512 || reopened.ExitRequestedAt != nil || reopened.ExitTargetAt != nil {
		t.Fatalf("expected reopened contribution to become active, got %+v", reopened)
	}

	// Idempotent replay of reopen after activation still returns the original 202 result; changed payload returns 409.
	replay, err := client.CommandContributionWithResponse(h.ctx, first.ID, &sdk.CommandContributionParams{IdempotencyKey: "reopen-one"}, sdk.CommandRequest{
		Revision:   first.Revision,
		Action:     sdk.Reopen,
		Conditions: &sdk.Conditions{LimitBytes: reopenCond.LimitBytes, PersonalReserve: reopenCond.PersonalReserve, Until: reopenCond.Until},
		Consent:    &sdk.Consent{Accepted: true, Version: reopenConsent.Version, Digest: reopenConsent.Digest},
	})
	must(t, err)
	if replay.StatusCode() != 202 || replay.JSON202 == nil || replay.JSON202.Revision != first.Revision+1 {
		t.Fatalf("expected idempotent replay 202, got %d %s", replay.StatusCode(), string(replay.Body))
	}
	mismatch, err := client.CommandContributionWithResponse(h.ctx, first.ID, &sdk.CommandContributionParams{IdempotencyKey: "reopen-one"}, sdk.CommandRequest{
		Revision:   first.Revision,
		Action:     sdk.Reopen,
		Conditions: &sdk.Conditions{LimitBytes: reopenCond.LimitBytes + 1, PersonalReserve: reopenCond.PersonalReserve, Until: reopenCond.Until},
		Consent:    &sdk.Consent{Accepted: true, Version: reopenConsent.Version, Digest: reopenConsent.Digest},
	})
	must(t, err)
	if mismatch.StatusCode() != 409 {
		t.Fatalf("expected 409 on mismatched replay payload, got %d", mismatch.StatusCode())
	}

	// Revoked contribution cannot be reopened and still counts against active quota.
	reopened = h.command(t, reopened, "revoke")
	h.run(t)
	revoked := h.get(t, first.ID)
	if revoked.State != "revoked" {
		t.Fatal(revoked)
	}
	if _, err := h.s.Command(h.ctx, user, revoked.ID, "reopen-revoked", contribution.CommandRequest{Revision: revoked.Revision, Action: "reopen", Conditions: &reopenCond, Consent: &reopenConsent}); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected conflict reopening revoked contribution, got %v", err)
	}
	qThree.Conditions.Until = h.clock.Now().Add(time.Hour)
	if _, err := h.s.Create(h.ctx, user, "create-three-blocked-by-revoked", qThree); !errors.Is(err, contribution.ErrConflict) {
		t.Fatalf("expected revoked contribution to retain quota slot, got %v", err)
	}
}

func (h *fixture) requestForExisting(id string) contribution.CreateRequest {
	return contribution.CreateRequest{
		InstanceID: id,
		Conditions: contribution.Conditions{LimitBytes: 1024, PersonalReserve: 100, Until: h.clock.Now().Add(time.Hour)},
		Consent:    contribution.Consent{Accepted: true, Version: h.cfg.Policy.Terms.Version, Digest: h.cfg.Policy.Terms.Digest},
	}
}
