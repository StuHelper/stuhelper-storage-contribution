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
	bound := map[string]bool{}
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		records, e := tx.List(p, registryLimit, "")
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
	// Storage can return short or empty pages with a continuation after its
	// own authorization-expiry filter. Continue until we have a visible lookahead.
	const batchSize = 100
	const maxBatches = 10
	for range maxBatches {
		page, err := s.store.ListContributionCandidates(ctx, s.cfg.Actor, OwnerDomain(p), batchSize, after)
		if err != nil {
			return storage.ContributionCandidates{}, storeError(err)
		}
		for _, item := range page.Items {
			if !bound[item.ID] && slices.Contains(s.cfg.Policy.Adapters, item.Adapter) {
				out.Items = append(out.Items, item)
				if len(out.Items) > n {
					break
				}
			}
		}
		if len(out.Items) > n {
			out.Items = out.Items[:n]
			out.NextCursor = out.Items[n-1].ID
			break
		}
		out.NextCursor = page.NextCursor
		if page.NextCursor == "" {
			break
		}
		if page.NextCursor <= after || !identifier.MatchString(page.NextCursor) {
			return storage.ContributionCandidates{}, ErrUnavailable
		}
		after = page.NextCursor
	}
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
	items, err := s.operationRows(ctx, p, f, false)
	if err != nil {
		return Page{}, err
	}
	for _, item := range items {
		if len(out.Items) == f.Limit {
			out.NextCursor = out.Items[f.Limit-1].ID
			break
		}
		out.Items = append(out.Items, item.view)
	}
	return out, nil
}

type operationRow struct {
	view    View
	pending int
}

func (s *Service) operationRows(ctx context.Context, p Principal, f OperationsFilter, metrics bool) ([]operationRow, error) {
	if !p.Valid() || (p == s.cfg.Actor && !metrics) {
		return nil, ErrDenied
	}
	batch, grouped := s.auth.(OperationReadAuthorizer)
	const action = "contributions.operations.read"
	if p == s.cfg.Actor {
		if err := s.authorize(ctx, p, "contributions.maintenance", Record{}); err != nil {
			return nil, err
		}
	} else if grouped {
		_, err := batch.AuthorizeOperationReads(ctx, p, nil)
		if errors.Is(err, ErrDenied) {
			return nil, ErrDenied
		}
		if err != nil {
			return nil, ErrUnavailable
		}
	} else if err := s.authorize(ctx, p, action, Record{}); err != nil {
		return nil, err
	}

	var records []Record
	var jobs map[string]Job
	var pending map[string]int
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		records, e = tx.ScanFiltered(registryLimit, f.After, f.State, "", f.Adapter)
		if e != nil {
			return e
		}
		ids := make([]string, len(records))
		for i, r := range records {
			ids[i] = r.View.ID
		}
		jobs, e = tx.JobsByIDs(ids)
		if e != nil {
			return e
		}
		if metrics {
			pending, e = tx.PendingOutboxBySubject(ids)
		}
		return e
	})
	if err != nil {
		return nil, err
	}
	out := make([]operationRow, 0, len(records))
	var allowed []bool
	if grouped && p != s.cfg.Actor {
		targets := make([]Access, len(records))
		for i, r := range records {
			targets[i] = Access{ID: r.View.ID, Owner: r.Owner}
		}
		allowed, err = batch.AuthorizeOperationReads(ctx, p, targets)
		if errors.Is(err, ErrDenied) {
			return nil, ErrDenied
		}
		if err != nil || len(allowed) != len(records) {
			return nil, ErrUnavailable
		}
	}
	for i, r := range records {
		if grouped && p != s.cfg.Actor {
			if !allowed[i] {
				continue
			}
		} else if p != s.cfg.Actor {
			if err := s.authorize(ctx, p, action, r); errors.Is(err, ErrDenied) {
				continue
			} else if err != nil {
				return nil, err
			}
		}
		v := s.view(r)
		if f.Reason != "" && v.Reason != f.Reason {
			continue
		}
		j, ok := jobs[v.ID]
		s.attachJob(&v, j, ok)
		out = append(out, operationRow{v, pending[v.ID]})
	}
	if p == s.cfg.Actor {
		err = s.authorize(ctx, p, "contributions.maintenance", Record{})
	} else if !grouped {
		err = s.authorize(ctx, p, action, Record{})
	}
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) MetricsSnapshot(ctx context.Context, p Principal) (MetricsSnapshot, error) {
	out := MetricsSnapshot{
		ByState:     map[string]int{},
		ByReason:    map[string]int{},
		ByJobState:  map[string]int{},
		GeneratedAt: s.now(),
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	rows, err := s.operationRows(ctx, p, OperationsFilter{}, true)
	if err != nil {
		return MetricsSnapshot{}, err
	}
	for _, row := range rows {
		v := row.view
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
		if v.JobState != "" {
			out.ByJobState[v.JobState]++
		}
		out.PendingOutbox += row.pending
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
		if v.Revision != q.Revision {
			return detailErr(ErrConflict, "revision_conflict")
		}
		if v.State != "blocked" {
			return detailErr(ErrConflict, "invalid_state_transition")
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
