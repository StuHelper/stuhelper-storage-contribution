package contribution_test

import (
	"context"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	contribution "github.com/StuHelper/stuhelper-storage-contribution"
	"testing"
	"time"
)

func TestPaginationAfterRegistrationLimitReduction(t *testing.T) {
	h := newFixture(t)
	for _, id := range []string{"a", "b", "c", "d"} {
		h.create(t, id)
	}
	for _, id := range []string{"e", "f"} {
		h.request(t, id)
	}
	cfg := h.cfg
	cfg.MaxContributions = 1
	cfg.Policy.MaxPerOwner = 1
	s, e := contribution.New(h.repo, h.policy, h.bridge, cfg)
	must(t, e)
	t.Run("options", func(t *testing.T) {
		page, e := s.Options(h.ctx, user, 1, "")
		must(t, e)
		if len(page.Items) != 1 || page.Items[0].ID != "e" || page.NextCursor != "e" {
			t.Fatal(page)
		}
		page, e = s.Options(h.ctx, user, 1, page.NextCursor)
		must(t, e)
		if len(page.Items) != 1 || page.Items[0].ID != "f" || page.NextCursor != "" {
			t.Fatal(page)
		}
		all, e := s.Options(h.ctx, user, 100, "")
		must(t, e)
		if len(all.Items) != 2 || all.Items[0].ID != "e" || all.Items[1].ID != "f" {
			t.Fatal(all)
		}
	})
	t.Run("statistics", func(t *testing.T) {
		stats, e := s.Statistics(h.ctx)
		must(t, e)
		if stats.Contributions != 4 || stats.DeclaredBytes != 4*1024 || stats.Status != "partial" {
			t.Fatal(stats)
		}
	})
}

type shortCandidatePages struct{ contribution.Store }

func (s shortCandidatePages) ListContributionCandidates(_ context.Context, _ contribution.Principal, _ string, _ int, after string) (storage.ContributionCandidates, error) {
	switch after {
	case "":
		return storage.ContributionCandidates{NextCursor: "a"}, nil
	case "a":
		return storage.ContributionCandidates{Items: []storage.ContributionCandidate{{ID: "b", Adapter: "disabled"}}, NextCursor: "b"}, nil
	case "b":
		return storage.ContributionCandidates{Items: []storage.ContributionCandidate{{ID: "c", Adapter: "fixture"}, {ID: "d", Adapter: "fixture"}}}, nil
	case "c":
		return storage.ContributionCandidates{Items: []storage.ContributionCandidate{{ID: "d", Adapter: "fixture"}}}, nil
	}
	return storage.ContributionCandidates{}, storage.ErrInput
}
func TestOptionsContinueAfterFilteredProviderPage(t *testing.T) {
	h := newFixture(t)
	s, e := contribution.New(h.repo, h.policy, shortCandidatePages{h.bridge}, h.cfg)
	must(t, e)
	first, e := s.Options(h.ctx, user, 1, "")
	must(t, e)
	if len(first.Items) != 1 || first.Items[0].ID != "c" || first.NextCursor != "c" {
		t.Fatal(first)
	}
	next, e := s.Options(h.ctx, user, 1, first.NextCursor)
	must(t, e)
	if len(next.Items) != 1 || next.Items[0].ID != "d" || next.NextCursor != "" {
		t.Fatal(next)
	}
}

func TestHistoryDoesNotHideBoundCandidatesOrCurrentTotals(t *testing.T) {
	h := newFixture(t)
	h.request(t, "bound-late")
	h.request(t, "free")
	must(t, h.repo.Transaction(h.ctx, func(tx contribution.Transaction) error {
		for i := 0; i < 101; i++ {
			id := fmt.Sprintf("archived-%03d", i)
			if err := tx.SaveRecord(contribution.Record{Owner: user, InstanceID: id, View: contribution.View{ID: id, State: "exited"}}); err != nil {
				return err
			}
		}
		return tx.SaveRecord(contribution.Record{Owner: user, InstanceID: "bound-late", View: contribution.View{ID: "z-current", State: "active", DesiredState: "active", Conditions: contribution.Conditions{LimitBytes: 123, Until: h.clock.Now().Add(time.Hour)}}})
	}))
	opts, err := h.s.Options(h.ctx, user, 100, "")
	must(t, err)
	if len(opts.Items) != 1 || opts.Items[0].ID != "free" {
		t.Fatal(opts)
	}
	stats, err := h.s.Statistics(h.ctx)
	must(t, err)
	if stats.Contributions != 1 || stats.DeclaredBytes != 123 {
		t.Fatal(stats)
	}
	metrics, err := h.s.MetricsSnapshot(h.ctx, system)
	must(t, err)
	if metrics.ByState["exited"] != 101 || metrics.ByState["active"] != 1 {
		t.Fatal(metrics)
	}
}
