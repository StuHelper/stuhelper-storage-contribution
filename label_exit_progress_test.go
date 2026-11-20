package contribution_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"github.com/StuHelper/stuhelper-storage-contribution/httpapi"
	"github.com/StuHelper/stuhelper-storage-contribution/sdk"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDisplayLabelPrivacyAndExitInitialBaseline(t *testing.T) {
	h := newFixture(t)
	qOne := h.request(t, "one")
	qTwo := h.request(t, "two")

	// Reject >32 Unicode characters on Create.
	tooLong := strings.Repeat("北", 33)
	badReq := qOne
	badReq.DisplayLabel = &tooLong
	if _, err := h.s.Create(h.ctx, user, "too-long", badReq); !errors.Is(err, contribution.ErrInput) {
		t.Fatalf("expected ErrInput for >32 char display_label, got %v", err)
	}

	// Control characters and surrounding spaces are stripped; 32 Unicode chars accepted.
	rawLabel := " \x00科研组\n北航网盘-A\t\x1f "
	qOne.DisplayLabel = &rawLabel
	created, err := h.s.Create(h.ctx, user, "create-one", qOne)
	must(t, err)
	const expectedLabel = "科研组北航网盘-A"
	if created.DisplayLabel != expectedLabel {
		t.Fatalf("expected sanitized display_label %q, got %q", expectedLabel, created.DisplayLabel)
	}

	// Owner Get & List return display_label.
	got := h.get(t, created.ID)
	if got.DisplayLabel != expectedLabel {
		t.Fatalf("expected owner Get display_label %q, got %q", expectedLabel, got.DisplayLabel)
	}
	listed, err := h.s.List(h.ctx, user, 20, "")
	must(t, err)
	if len(listed.Items) != 1 || listed.Items[0].DisplayLabel != expectedLabel {
		t.Fatalf("expected owner List display_label, got %+v", listed.Items)
	}

	// Reject display_label on non-configure actions (e.g. pause).
	otherLabel := "不应生效"
	if _, err := h.s.Command(h.ctx, user, created.ID, "bad-pause-label", contribution.CommandRequest{
		Revision: created.Revision, Action: "pause", DisplayLabel: &otherLabel,
	}); !errors.Is(err, contribution.ErrInput) {
		t.Fatalf("expected ErrInput for display_label on pause, got %v", err)
	}

	// Admin Operations, Admin RetryOperation, Statistics and Outbox MUST strip display_label!
	h.bridge.fail = true
	for range 3 {
		_ = h.s.RunOne(h.ctx, "worker")
		h.clock.Add(10 * time.Second)
	}
	ops, err := h.s.Operations(h.ctx, operator, 20, "")
	must(t, err)
	opsJSON, err := json.Marshal(ops)
	must(t, err)
	if bytes.Contains(opsJSON, []byte(expectedLabel)) || bytes.Contains(opsJSON, []byte("display_label")) {
		t.Fatalf("display_label leaked in Operations: %s", string(opsJSON))
	}

	retried, err := h.s.RetryOperation(h.ctx, operator, created.ID, "admin-retry", contribution.RetryRequest{Revision: h.get(t, created.ID).Revision})
	must(t, err)
	retriedJSON, err := json.Marshal(retried)
	must(t, err)
	if retried.DisplayLabel != "" || bytes.Contains(retriedJSON, []byte(expectedLabel)) || bytes.Contains(retriedJSON, []byte("display_label")) {
		t.Fatalf("display_label leaked in RetryOperation: %s", string(retriedJSON))
	}

	events, err := h.repo.PendingEvents(h.ctx, 100)
	must(t, err)
	eventsJSON, err := json.Marshal(events)
	must(t, err)
	if bytes.Contains(eventsJSON, []byte(expectedLabel)) || bytes.Contains(eventsJSON, []byte("display_label")) {
		t.Fatalf("display_label leaked in outbox events: %s", string(eventsJSON))
	}

	// Activate, update label via HTTP SDK configure (and preserve when omitted), then verify exit initial baseline.
	h.bridge.fail = false
	h.run(t)
	active := h.get(t, created.ID)
	if active.DisplayLabel != expectedLabel {
		t.Fatalf("expected label preserved across worker run, got %q", active.DisplayLabel)
	}

	handler, err := httpapi.New(h.s, fixtureAuth{})
	must(t, err)
	srv := httptest.NewServer(handler)
	defer srv.Close()
	client, err := sdk.NewClientWithResponses(srv.URL, sdk.WithRequestEditorFn(func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer fixture")
		return nil
	}))
	must(t, err)

	updatedLabel := strings.Repeat("北", 32)
	paddedLabel := "　" + updatedLabel + "\t "
	condSDK := sdk.Conditions{LimitBytes: active.Conditions.LimitBytes, PersonalReserve: active.Conditions.PersonalReserve, Until: active.Conditions.Until}
	cfgResp, err := client.CommandContributionWithResponse(h.ctx, active.ID, &sdk.CommandContributionParams{IdempotencyKey: "cfg-label"}, sdk.CommandRequest{
		Revision: active.Revision, Action: sdk.Configure, DisplayLabel: &paddedLabel,
	})
	must(t, err)
	if cfgResp.JSON202 == nil || cfgResp.JSON202.DisplayLabel == nil || *cfgResp.JSON202.DisplayLabel != updatedLabel || cfgResp.JSON202.Conditions != condSDK {
		t.Fatalf("expected updated display_label in 202 response, got %d %s", cfgResp.StatusCode(), string(cfgResp.Body))
	}
	h.run(t)

	// Configure without display_label preserves existing label.
	active = h.get(t, active.ID)
	condSDK.PersonalReserve = 120
	preserveResp, err := client.CommandContributionWithResponse(h.ctx, active.ID, &sdk.CommandContributionParams{IdempotencyKey: "cfg-preserve"}, sdk.CommandRequest{
		Revision: active.Revision, Action: sdk.Configure, Conditions: &condSDK,
	})
	must(t, err)
	if preserveResp.JSON202 == nil || preserveResp.JSON202.DisplayLabel == nil || *preserveResp.JSON202.DisplayLabel != updatedLabel {
		t.Fatalf("expected omitted display_label to preserve %q, got %s", updatedLabel, string(preserveResp.Body))
	}
	h.run(t)

	active = h.get(t, active.ID)
	empty := ""
	clearNote := sdk.CommandRequest{Revision: active.Revision, Action: sdk.Configure, DisplayLabel: &empty}
	clearKey := &sdk.CommandContributionParams{IdempotencyKey: "cfg-clear"}
	for range 2 {
		resp, err := client.CommandContributionWithResponse(h.ctx, active.ID, clearKey, clearNote)
		must(t, err)
		if resp.JSON202 == nil || resp.JSON202.DisplayLabel != nil || resp.JSON202.Conditions != condSDK || resp.JSON202.Revision != active.Revision+1 {
			t.Fatal("clear and replay must preserve conditions and advance only one revision", resp.StatusCode())
		}
	}
	h.run(t)
	if got := h.get(t, active.ID); got.DisplayLabel != "" {
		t.Fatal("clear did not persist")
	}

	// Ingest 24 bytes onto "one", sync observation, then exit and verify exit_initial_replicas & exit_initial_used_bytes stay pinned through cleanup!
	payload := strings.Repeat("p", 24)
	sum := sha256.Sum256([]byte(payload))
	obj, err := h.store.Create(h.ctx, system, "exit-baseline-obj", storage.CreateRequest{
		Size: 24, SHA256: hex.EncodeToString(sum[:]),
		Protection: storage.Protection{Class: "public", Scope: "school", Public: true},
	})
	must(t, err)
	_, err = h.store.Ingest(h.ctx, system, obj.ID, "write-baseline", strings.NewReader(payload))
	must(t, err)

	// Trigger exit even before polling the new replica: initial baseline captures 0 from stale observation, then upgrades to 1 replica / 24 bytes on draining sync!
	active = h.get(t, active.ID)
	exiting := h.command(t, active, "exit")
	if exiting.ExitInitialReplicas == nil || exiting.ExitInitialUsedBytes == nil {
		t.Fatalf("expected immediate exit baseline snapshot on exit command, got %+v", exiting)
	}
	h.run(t)
	exiting = h.get(t, active.ID)
	if exiting.State != "exiting" || exiting.ExitInitialReplicas == nil || *exiting.ExitInitialReplicas != 1 || exiting.ExitInitialUsedBytes == nil || *exiting.ExitInitialUsedBytes != 24 {
		t.Fatalf("expected authoritative draining baseline (1 replica, 24 bytes), got %+v", exiting)
	}

	// Delete object so remaining_replicas and used_bytes drop to 0 -> exited still retains initial baseline (1, 24) for 100% completion display!
	_, err = h.store.Delete(h.ctx, system, obj.ID, "delete-baseline", obj.Revision)
	must(t, err)
	_, err = h.store.RunOne(h.ctx, "storage-worker")
	must(t, err)
	h.clock.Add(time.Minute)
	h.run(t)
	done := h.get(t, active.ID)
	if done.State != "exited" || done.Observation.RemainingReplicas != 0 || done.Observation.UsedBytes != 0 || done.ExitInitialReplicas == nil || *done.ExitInitialReplicas != 1 || done.ExitInitialUsedBytes == nil || *done.ExitInitialUsedBytes != 24 {
		t.Fatalf("expected exited record to retain initial baseline (1, 24), got %+v", done)
	}

	// Also verify exiting BEFORE any Observation exists backfills baseline on first draining sync.
	two, err := h.s.Create(h.ctx, user, "create-two", qTwo)
	must(t, err)
	two = h.command(t, two, "exit")
	if two.ExitInitialReplicas != nil || two.ExitInitialUsedBytes != nil {
		t.Fatalf("expected nil baseline prior to first observation, got %+v", two)
	}
	h.run(t)
	twoDone := h.get(t, two.ID)
	if twoDone.State != "exited" || twoDone.ExitInitialReplicas == nil || *twoDone.ExitInitialReplicas != 0 || twoDone.ExitInitialUsedBytes == nil || *twoDone.ExitInitialUsedBytes != 0 {
		t.Fatalf("expected backfilled zero baseline on unobserved exit, got %+v", twoDone)
	}
}
