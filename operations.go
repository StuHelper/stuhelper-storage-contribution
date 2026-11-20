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
		if errors.Is(e, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.read", "options", p.Issuer)
		}
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
		ids := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			ids = append(ids, item.ID)
		}
		var bound map[string]bool
		if err = s.repo.Transaction(ctx, func(tx Transaction) error {
			var e error
			bound, e = tx.BoundInstances(p, ids)
			return e
		}); err != nil {
			return storage.ContributionCandidates{}, err
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
	if e := s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
		if errors.Is(e, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.read", "options", p.Issuer)
		}
		return storage.ContributionCandidates{}, e
	}
	owners := make(map[string]string, len(out.Items))
	owner := OwnerDomain(p)
	for _, item := range out.Items {
		owners[item.ID] = owner
	}
	hints := s.store.ContributionAccountHints(ctx, s.cfg.Actor, owners)
	for i := range out.Items {
		out.Items[i].AccountHint = hints[out.Items[i].ID]
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
	rows := make([]operationRow, 0, f.Limit)
	err := s.visitOperationRows(ctx, p, f, false, func(items []operationRow) bool {
		for _, item := range items {
			if len(out.Items) == f.Limit {
				out.NextCursor = out.Items[f.Limit-1].ID
				return false
			}
			out.Items = append(out.Items, item.view)
			rows = append(rows, item)
		}
		return true
	})
	if err != nil {
		if errors.Is(err, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.operations.read", "operations", p.Issuer)
		}
		return Page{}, err
	}
	err = s.repo.Transaction(ctx, func(tx Transaction) error {
		return tx.Audit(AuditEntry{ID: s.nextAuditID("operations-read", p, "contributions.operations.read", "operations"), Actor: p, Action: "contributions.operations.read", Target: "operations", School: "*", Result: "success", Time: s.now()})
	})
	if err != nil {
		return Page{}, err
	}
	owners := make(map[string]string, len(rows))
	for _, row := range rows {
		owners[row.instanceID] = row.ownerDomain
	}
	hints := s.store.ContributionAccountHints(ctx, s.cfg.Actor, owners)
	for i, row := range rows {
		out.Items[i].AccountHint = hints[row.instanceID]
	}
	return out, nil
}

type operationRow struct {
	view        View
	pending     int
	instanceID  string
	ownerDomain string
}

func (s *Service) visitOperationRows(ctx context.Context, p Principal, f OperationsFilter, metrics bool, visit func([]operationRow) bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		rows, next, err := s.operationRows(ctx, p, f, metrics)
		if err != nil {
			return err
		}
		if !visit(rows) || next == "" {
			return nil
		}
		if next <= f.After {
			return ErrUnavailable
		}
		f.After = next
	}
}
func (s *Service) operationRows(ctx context.Context, p Principal, f OperationsFilter, metrics bool) ([]operationRow, string, error) {
	if !p.Valid() || (p == s.cfg.Actor && !metrics) {
		return nil, "", ErrDenied
	}
	batch, grouped := s.auth.(OperationReadAuthorizer)
	const action = "contributions.operations.read"
	if p == s.cfg.Actor {
		if err := s.authorize(ctx, p, "contributions.maintenance", Record{}); err != nil {
			return nil, "", err
		}
	} else if grouped {
		_, err := batch.AuthorizeOperationReads(ctx, p, nil)
		if errors.Is(err, ErrDenied) {
			return nil, "", ErrDenied
		}
		if err != nil {
			return nil, "", ErrUnavailable
		}
	} else if err := s.authorize(ctx, p, action, Record{}); err != nil {
		return nil, "", err
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
		return nil, "", err
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
			return nil, "", ErrDenied
		}
		if err != nil || len(allowed) != len(records) {
			return nil, "", ErrUnavailable
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
				return nil, "", err
			}
		}
		v := s.view(r)
		if f.Reason != "" && v.Reason != f.Reason {
			continue
		}
		j, ok := jobs[v.ID]
		s.attachJob(&v, j, ok)
		row := operationRow{view: v, pending: pending[v.ID]}
		if !metrics {
			row.instanceID = r.InstanceID
			row.ownerDomain = OwnerDomain(r.Owner)
		}
		out = append(out, row)
	}
	if p == s.cfg.Actor {
		err = s.authorize(ctx, p, "contributions.maintenance", Record{})
	} else if !grouped {
		err = s.authorize(ctx, p, action, Record{})
	}
	if err != nil {
		return nil, "", err
	}
	next := ""
	if len(records) == registryLimit {
		next = records[len(records)-1].View.ID
	}
	return out, next, nil
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
	err := s.visitOperationRows(ctx, p, OperationsFilter{}, true, func(rows []operationRow) bool {
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
		return true
	})
	if err != nil {
		return MetricsSnapshot{}, err
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
