package contribution

import (
	"context"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"slices"
)

var validOperationStates = []string{"pending", "active", "paused", "exiting", "blocked", "exited", "revoked"}
var validOperationReasons = []string{"consent_expired", "observation_stale", "storage_unavailable", "authorization_required", "storage_conflict", "binding_unavailable", "cleanup_unconfirmed", "storage_writes_disabled", "capacity_unknown", "exit_overdue"}

// Options derives ownership from the verified principal, never a query field.
func (s *Service) Options(ctx context.Context, p Principal, n int, after string) (storage.ContributionCandidates, error) {
	out := storage.ContributionCandidates{Items: []storage.ContributionCandidate{}}
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
		return out, e
	}
	page, e := s.store.ListContributionCandidates(ctx, s.cfg.Actor, OwnerDomain(p), n, after)
	if e != nil {
		return out, storeError(e)
	}
	bound := map[string]bool{}
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		records, e := tx.List(p, s.cfg.Policy.MaxPerOwner+1, "")
		if e != nil {
			return e
		}
		for _, r := range records {
			bound[r.InstanceID] = true
		}
		return nil
	})
	if e != nil {
		return out, e
	}
	for _, i := range page.Items {
		if !bound[i.ID] && slices.Contains(s.cfg.Policy.Adapters, i.Adapter) {
			out.Items = append(out.Items, i)
		}
	}
	out.NextCursor = page.NextCursor
	if e = s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
		return storage.ContributionCandidates{}, e
	}
	return out, nil
}
func (s *Service) attachJob(v *View, j Job, ok bool) {
	if !ok {
		return
	}
	attempts := j.Attempts
	maxAttempts := s.cfg.MaxAttempts
	v.JobState = j.State
	v.Attempts = &attempts
	v.MaxAttempts = &maxAttempts
	if !j.AvailableAt.IsZero() {
		at := j.AvailableAt.UTC()
		v.AvailableAt = &at
	}
}
func (s *Service) Operations(ctx context.Context, p Principal, n int, after string) (Page, error) {
	return s.OperationsFiltered(ctx, p, OperationsFilter{Limit: n, After: after})
}
func (s *Service) OperationsFiltered(ctx context.Context, p Principal, f OperationsFilter) (Page, error) {
	out := Page{Items: []View{}}
	if f.Limit < 1 || f.Limit > 100 || (f.After != "" && !identifier.MatchString(f.After)) || (f.State != "" && !slices.Contains(validOperationStates, f.State)) || (f.Reason != "" && !slices.Contains(validOperationReasons, f.Reason)) || (f.Adapter != "" && !identifier.MatchString(f.Adapter)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	staticReason := f.Reason
	if staticReason == "observation_stale" || staticReason == "consent_expired" {
		staticReason = ""
	}
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := s.authorize(ctx, p, "contributions.operations.read", Record{}); e != nil {
			return e
		}
		cursor := f.After
		batchSize := max(f.Limit+1, 25)
		collected := make([]View, 0, f.Limit+1)
		for page := 0; page < 20 && len(collected) <= f.Limit; page++ {
			rs, e := tx.ScanFiltered(batchSize, cursor, f.State, staticReason, f.Adapter)
			if e != nil {
				return e
			}
			if len(rs) == 0 {
				break
			}
			cursor = rs[len(rs)-1].View.ID
			for _, r := range rs {
				if e = s.authorize(ctx, p, "contributions.operations.read", r); e != nil {
					if errors.Is(e, ErrDenied) {
						continue
					}
					return e
				}
				v := s.view(r)
				if f.State != "" && v.State != f.State {
					continue
				}
				if f.Reason != "" && v.Reason != f.Reason {
					continue
				}
				if f.Adapter != "" && v.Adapter != f.Adapter {
					continue
				}
				collected = append(collected, v)
				if len(collected) > f.Limit {
					break
				}
			}
			if len(rs) < batchSize {
				break
			}
		}
		if len(collected) > f.Limit {
			collected = collected[:f.Limit]
			out.NextCursor = collected[f.Limit-1].ID
		}
		ids := make([]string, 0, len(collected))
		for _, v := range collected {
			ids = append(ids, v.ID)
		}
		jobs, e := tx.JobsByIDs(ids)
		if e != nil {
			return e
		}
		for _, v := range collected {
			j, ok := jobs[v.ID]
			s.attachJob(&v, j, ok)
			out.Items = append(out.Items, v)
		}
		return s.authorize(ctx, p, "contributions.operations.read", Record{})
	})
	return out, e
}
func (s *Service) MetricsSnapshot(ctx context.Context, p Principal) (MetricsSnapshot, error) {
	out := MetricsSnapshot{
		ByState:     map[string]int{},
		ByReason:    map[string]int{},
		ByJobState:  map[string]int{},
		GeneratedAt: s.now(),
	}
	action := "contributions.operations.read"
	if p == s.cfg.Actor {
		action = "contributions.maintenance"
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, p, action, Record{}); e != nil {
		return out, e
	}
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		cursor := ""
		for page := 0; page < 50; page++ {
			rs, e := tx.Scan(100, cursor)
			if e != nil {
				return e
			}
			if len(rs) == 0 {
				break
			}
			cursor = rs[len(rs)-1].View.ID
			for _, r := range rs {
				if action == "contributions.operations.read" {
					if e = s.authorize(ctx, p, action, r); e != nil {
						if errors.Is(e, ErrDenied) {
							continue
						}
						return e
					}
				}
				v := s.view(r)
				out.ByState[v.State]++
				if v.Reason != "" {
					out.ByReason[v.Reason]++
				}
				if v.Reason == "exit_overdue" || (v.DesiredState == "exiting" && v.State != "exited" && v.ExitTargetAt != nil && !v.ExitTargetAt.After(s.now())) {
					out.ExitOverdue++
				}
				if v.Reason == "cleanup_unconfirmed" {
					out.CleanupUnconfirmed++
				}
			}
			if len(rs) < 100 {
				break
			}
		}
		jobs, e := tx.JobTotals()
		if e != nil {
			return e
		}
		out.ByJobState = jobs
		pendingOutbox, e := tx.PendingOutboxCount()
		if e != nil {
			return e
		}
		out.PendingOutbox = pendingOutbox
		return s.authorize(ctx, p, action, Record{})
	})
	if e != nil {
		return MetricsSnapshot{}, e
	}
	return out, nil
}

type RetryRequest struct {
	Revision int64 `json:"revision"`
}

func (s *Service) RetryOperation(ctx context.Context, p Principal, id, key string, q RetryRequest) (View, error) {
	if q.Revision < 1 || id == "" {
		return View{}, ErrInput
	}
	out, e := s.mutation(ctx, p, "contributions.operations.retry", id, key, q, func(_ Transaction, r *Record) error {
		v := &r.View
		if v.Revision != q.Revision || v.State != "blocked" {
			return ErrConflict
		}
		v.Revision++
		v.State = "pending"
		v.Reason = ""
		return nil
	})
	if e != nil {
		return View{}, e
	}
	readCtx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	_ = s.repo.Transaction(readCtx, func(tx Transaction) error {
		jobs, err := tx.JobsByIDs([]string{out.ID})
		if err == nil {
			j, ok := jobs[out.ID]
			s.attachJob(&out, j, ok)
		}
		return nil
	})
	return out, nil
}
