package contribution_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"testing"
	"time"
)

type inspectCounter struct {
	contribution.Store
	calls int
	err   error
}

func (s *inspectCounter) InspectContribution(ctx context.Context, p contribution.Principal, id, owner string) (storage.ContributionSnapshot, error) {
	s.calls++
	if s.err != nil {
		return storage.ContributionSnapshot{}, s.err
	}
	return s.Store.InspectContribution(ctx, p, id, owner)
}
func TestCreateValidatesAndReplaysBeforeStorage(t *testing.T) {
	h := newFixture(t)
	st := &inspectCounter{Store: h.bridge}
	s, e := contribution.New(h.repo, h.policy, st, h.cfg)
	must(t, e)
	q := h.request(t, "one")
	invalid := q
	invalid.Consent.Accepted = false
	for _, c := range []struct {
		key string
		req contribution.CreateRequest
	}{{"", q}, {"bad-consent", invalid}} {
		if _, e := s.Create(h.ctx, user, c.key, c.req); !errors.Is(e, contribution.ErrInput) || st.calls != 0 {
			t.Fatalf("invalid request: %v, inspections=%d", e, st.calls)
		}
	}
	q.Conditions.Until = q.Conditions.Until.In(time.FixedZone("UTC+8", 8*3600))
	created, e := s.Create(h.ctx, user, "_+/= key", q)
	must(t, e)
	st.err = storage.ErrUnavailable
	original, err := json.Marshal(q)
	must(t, err)
	legacyHash := fmt.Sprintf("%x", sha256.Sum256(original))
	q.Conditions.Until = q.Conditions.Until.UTC()
	got, e := s.Create(h.ctx, user, "_+/= key", q)
	must(t, e)
	if got.ID != created.ID || got.Revision != created.Revision || st.calls != 1 {
		t.Fatal(got, st.calls)
	}
	// Older receipts hashed the original offset. A replay must also survive
	// expiry of the requested term during the 24-hour receipt window.
	_, e = h.admin.Exec(`UPDATE contribution.replays SET data=jsonb_set(data,'{Hash}',to_jsonb($1::text))`, legacyHash)
	must(t, e)
	h.clock.Add(2 * time.Hour)
	got, e = s.Create(h.ctx, user, "_+/= key", q)
	must(t, e)
	if got.ID != created.ID || st.calls != 1 {
		t.Fatal(got, st.calls)
	}
	q.InstanceID = "another"
	if _, e := s.Create(h.ctx, user, "_+/= key", q); !errors.Is(e, contribution.ErrConflict) || st.calls != 1 {
		t.Fatal(e, st.calls)
	}
	q.Conditions.Until = h.clock.Now().Add(time.Hour)
	for _, cause := range []error{storage.ErrDenied, storage.ErrNotFound} {
		st.err = cause
		if _, e := s.Create(h.ctx, user, "new-key", q); !errors.Is(e, contribution.ErrNotFound) {
			t.Fatal(e)
		}
	}
	var records, jobs, events, replays int
	must(t, h.admin.QueryRow(`SELECT (SELECT count(*) FROM contribution.contributions),(SELECT count(*) FROM contribution.jobs),(SELECT count(*) FROM contribution.outbox),(SELECT count(*) FROM contribution.replays)`).Scan(&records, &jobs, &events, &replays))
	if records != 1 || jobs != 1 || events != 1 || replays != 1 {
		t.Fatal(records, jobs, events, replays)
	}
}
