package contribution

import (
	"context"
	"errors"
	"fmt"
	storage "github.com/StuHelper/stuhelper-storage"
	"math"
	"math/bits"
	"time"
)

var (
	errRetryableStale  = fmt.Errorf("%w: concurrent storage revision", ErrConflict)
	errPendingExitAuth = fmt.Errorf("%w: exit awaiting authorization or consent expiry", ErrDenied)
)

func storeError(e error) error {
	switch {
	case e == nil:
		return nil
	case errors.Is(e, storage.ErrDenied):
		return ErrDenied
	case errors.Is(e, storage.ErrNotFound):
		return ErrNotFound
	case errors.Is(e, storage.ErrConflict), errors.Is(e, storage.ErrStale), errors.Is(e, storage.ErrCapacity):
		return ErrConflict
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded):
		return e
	default:
		return ErrUnavailable
	}
}

func materialView(v View) View {
	v.UpdatedAt = time.Time{}
	if v.Observation != nil {
		o := *v.Observation
		o.ObservedAt = time.Time{}
		v.Observation = &o
	}
	return v
}

// Multiply in 128 bits: byte-nanoseconds can exceed uint64 even for
// ordinary quotas. Existing byte-second remainders keep their original unit.
func addByteHours(hours *int64, remSecs, remNanos *uint64, bytes int64, duration time.Duration) {
	if bytes <= 0 || duration <= 0 {
		return
	}
	hi, lo := bits.Mul64(uint64(bytes), uint64(duration))
	lo, carry := bits.Add64(lo, *remSecs*uint64(time.Second)+*remNanos, 0)
	hi += carry
	added, left := bits.Div64(hi, lo, uint64(time.Hour))
	*remSecs = left / uint64(time.Second)
	*remNanos = left % uint64(time.Second)
	if added > uint64(math.MaxInt64-*hours) {
		*hours = math.MaxInt64
	} else {
		*hours += int64(added)
	}
}
func accumulateVerifiedUsage(r *Record, snapshot storage.ContributionSnapshot, maxAgeSeconds int64) {
	prev := r.View.Observation
	if prev == nil || r.View.State != "active" || r.View.DesiredState != "active" || !prev.Authorized || !snapshot.Authorized || snapshot.State != "active" {
		return
	}
	start := prev.ObservedAt
	maxEnd := start.Add(time.Duration(maxAgeSeconds) * time.Second)
	if !snapshot.ObservedAt.After(start) || snapshot.ObservedAt.After(maxEnd) {
		return
	}
	end := snapshot.ObservedAt
	for _, bound := range []time.Time{prev.AuthorizationExpiresAt, snapshot.AuthorizationExpiresAt, r.View.Conditions.Until} {
		if bound.Before(end) {
			end = bound
		}
	}
	dt := end.Sub(start)
	if dt <= 0 {
		return
	}
	ns := uint64(dt) + r.VerifiedActiveNanos
	r.VerifiedActiveSeconds += int64(ns / uint64(time.Second))
	r.VerifiedActiveNanos = ns % uint64(time.Second)
	addByteHours(&r.VerifiedUsedByteHours, &r.VerifiedUsedRemByteSecs, &r.VerifiedUsedRemByteNanos, min(prev.UsedBytes, snapshot.UsedBytes), dt)
	availEnd := end
	if prev.QuotaExpiresAt.Before(availEnd) {
		availEnd = prev.QuotaExpiresAt
	}
	if snapshot.QuotaExpiresAt.Before(availEnd) {
		availEnd = snapshot.QuotaExpiresAt
	}
	if availDt := availEnd.Sub(start); availDt > 0 {
		addByteHours(&r.VerifiedAvailableByteHours, &r.VerifiedAvailableRemByteSecs, &r.VerifiedAvailableRemByteNanos, min(prev.AvailableBytes, snapshot.AvailableBytes), availDt)
	}
}

// Sweep converts expired consent into a durable exit request, including blocked
// activation jobs. Storage independently stops writes at the consent deadline.
func (s *Service) Sweep(ctx context.Context, n int, after string) (string, error) {
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return "", ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
		return "", e
	}
	var next string
	changed := false
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		rs, e := tx.Scan(n, after)
		if e != nil {
			return e
		}
		if len(rs) == n {
			next = rs[len(rs)-1].View.ID
		}
		now := s.now()
		for _, item := range rs {
			if (item.View.DesiredState != "active" && item.View.DesiredState != "paused") || item.View.Conditions.Until.After(now) {
				continue
			}
			r, e := tx.Record(item.View.ID)
			if e != nil {
				return e
			}
			v := &r.View
			if (v.DesiredState == "active" || v.DesiredState == "paused") && !v.Conditions.Until.After(s.now()) {
				s.exit(v)
				v.Revision++
				v.State = "pending"
				v.Reason = "consent_expired"
				if e = s.emit(tx, s.cfg.Actor, "contribution.expired", &r); e != nil {
					return e
				}
				if e = s.enqueue(tx, r); e != nil {
					return e
				}
				changed = true
			}
		}
		if e = s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
			return e
		}
		if pruner, ok := tx.(interface {
			PruneReplaysCount(time.Time, int) (int, error)
		}); ok {
			const pruneLimit = 1000
			deleted, err := pruner.PruneReplaysCount(now, pruneLimit)
			if err == nil && deleted == pruneLimit && next == "" {
				// Contribution IDs are hex digests. This cursor resumes cleanup past the last record.
				next = "replay-prune"
			}
			return err
		}
		return tx.PruneReplays(s.now(), 100)
	})
	if e == nil && changed {
		s.invalidateStatistics()
	}
	return next, e
}
func (s *Service) RunOne(runCtx context.Context, worker string) error {
	if !identifier.MatchString(worker) {
		return ErrInput
	}
	dbTimeout := min(s.cfg.OperationTimeout, s.cfg.Lease/4)
	syncTimeout := min(s.cfg.OperationTimeout, s.cfg.Lease/2)
	claimCtx, cancelClaim := context.WithTimeout(runCtx, dbTimeout)
	if e := s.authorize(claimCtx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
		cancelClaim()
		return e
	}
	j, e := s.repo.Claim(claimCtx, worker, s.now(), s.cfg.Lease)
	if e != nil {
		cancelClaim()
		return e
	}
	var r Record
	e = s.repo.Transaction(claimCtx, func(tx Transaction) error {
		var e error
		r, e = tx.Record(j.ID)
		if e != nil {
			return e
		}
		current, e := tx.Job(j.ID)
		if e != nil {
			return e
		}
		if current.Generation != j.Generation || current.State != "running" {
			return ErrConflict
		}
		return nil
	})
	cancelClaim()
	if e != nil {
		return e
	}
	var snapshot storage.ContributionSnapshot
	var hasSnapshot bool
	operationErr := ErrUnavailable
	if j.Attempts <= s.cfg.MaxAttempts {
		syncCtx, cancelSync := context.WithTimeout(runCtx, syncTimeout)
		snapshot, hasSnapshot, operationErr = s.synchronize(syncCtx, r)
		cancelSync()
	}
	// A canceled caller attempt leaves its lease for another process; no unbounded
	// detached write or retry is started during shutdown.
	if runCtx.Err() != nil {
		return runCtx.Err()
	}
	if errors.Is(operationErr, context.DeadlineExceeded) || errors.Is(operationErr, context.Canceled) {
		operationErr = ErrUnavailable
	}
	saveCtx, cancelSave := context.WithTimeout(runCtx, dbTimeout)
	defer cancelSave()
	e = s.repo.Transaction(saveCtx, func(tx Transaction) error {
		current, e := tx.Record(j.ID)
		if e != nil {
			return e
		}
		job, e := tx.Job(j.ID)
		if e != nil {
			return e
		}
		if job.Generation != j.Generation || job.LeaseOwner != worker || job.State != "running" || !job.LeaseUntil.After(s.now()) || current.View.Revision != r.View.Revision {
			return ErrConflict
		}
		if e = s.authorize(saveCtx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
			return e
		}
		before := hash(materialView(current.View))
		v := &current.View
		if hasSnapshot {
			if operationErr == nil {
				accumulateVerifiedUsage(&current, snapshot, s.cfg.Policy.ObservationMaxAgeSeconds)
			}
			v.Observation = &Observation{snapshot.ObservedAt, snapshot.AuthorizationExpiresAt, snapshot.QuotaExpiresAt, snapshot.Authorized, snapshot.UsedBytes, snapshot.ReservedBytes, snapshot.AvailableBytes, snapshot.RemainingReplicas}
		}
		if operationErr != nil {
			if errors.Is(operationErr, errPendingExitAuth) {
				v.State = "blocked"
				v.Reason = "authorization_required"
				job.Attempts = 0
				job.State = "pending"
				job.AvailableAt = s.now().Add(s.cfg.RefreshInterval)
			} else {
				job.Attempts = j.Attempts
				v.Reason = "storage_unavailable"
				switch {
				case errors.Is(operationErr, ErrDenied):
					v.Reason = "authorization_required"
				case errors.Is(operationErr, ErrConflict):
					v.Reason = "storage_conflict"
				case errors.Is(operationErr, ErrNotFound):
					v.Reason = "binding_unavailable"
				}
				v.State = "blocked"
				job.State = "pending"
				job.AvailableAt = s.now().Add(time.Duration(1<<uint(job.Attempts)) * time.Second)
				retryable := errors.Is(operationErr, ErrUnavailable) || errors.Is(operationErr, errRetryableStale)
				if job.Attempts >= s.cfg.MaxAttempts || !retryable {
					job.State = "blocked"
				}
			}
		} else {
			if snapshot.Control != nil {
				v.AppliedRevision = snapshot.Control.Revision
			}
			v.Reason = ""
			v.State = v.DesiredState
			if v.DesiredState == "exiting" {
				replicas := snapshot.RemainingReplicas
				used := snapshot.UsedBytes
				if v.ExitInitialReplicas != nil && *v.ExitInitialReplicas > replicas {
					replicas = *v.ExitInitialReplicas
				}
				if v.ExitInitialUsedBytes != nil && *v.ExitInitialUsedBytes > used {
					used = *v.ExitInitialUsedBytes
				}
				v.ExitInitialReplicas = &replicas
				v.ExitInitialUsedBytes = &used
			}
			job.Attempts = 0
			job.State = "pending"
			job.AvailableAt = s.now().Add(s.cfg.RefreshInterval)
			switch {
			case v.DesiredState == "revoked":
				if snapshot.RemainingReplicas > 0 || snapshot.UsedBytes > 0 || snapshot.ReservedBytes > 0 {
					v.Reason = "cleanup_unconfirmed"
				} else {
					job.State = "complete"
				}
			case v.DesiredState == "exiting" && snapshot.RemainingReplicas == 0 && snapshot.UsedBytes == 0 && snapshot.ReservedBytes == 0:
				v.State = "exited"
				job.State = "complete"
			case !snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now()):
				v.State = "blocked"
				v.Reason = "authorization_required"
			case snapshot.State != "active" && v.DesiredState == "active":
				v.State = "blocked"
				v.Reason = "storage_writes_disabled"
			case v.DesiredState == "active" && !snapshot.QuotaExpiresAt.After(s.now()):
				v.Reason = "capacity_unknown"
			}
			if v.DesiredState == "exiting" && v.State != "exited" && v.ExitTargetAt != nil && !v.ExitTargetAt.After(s.now()) && v.Reason == "" {
				v.Reason = "exit_overdue"
			}
		}
		job.LeaseUntil = time.Time{}
		job.LeaseOwner = ""
		if hash(materialView(current.View)) != before {
			if e = s.emit(tx, s.cfg.Actor, "contribution.observed", &current); e != nil {
				return e
			}
		} else if e = tx.SaveRecord(current); e != nil {
			return e
		}
		return tx.SaveJob(job)
	})
	if e != nil {
		return e
	}
	s.invalidateStatistics()
	return operationErr
}
func (s *Service) validSnapshot(r Record, snapshot storage.ContributionSnapshot) bool {
	now := s.now()
	return snapshot.InstanceID == r.InstanceID && snapshot.Adapter == r.View.Adapter && !snapshot.ObservedAt.After(now.Add(time.Second)) && !snapshot.ObservedAt.Before(now.Add(-s.cfg.OperationTimeout))
}
func (s *Service) synchronize(ctx context.Context, r Record) (storage.ContributionSnapshot, bool, error) {
	v := r.View
	snapshot, e := s.store.InspectContribution(ctx, s.cfg.Actor, r.InstanceID, OwnerDomain(r.Owner))
	if e != nil {
		return snapshot, false, storeError(e)
	}
	if !s.validSnapshot(r, snapshot) {
		return snapshot, false, ErrUnavailable
	}
	if snapshot.Control != nil && (snapshot.Control.ID != v.ID || snapshot.Control.Revision > v.Revision) {
		return snapshot, true, ErrConflict
	}
	if e = s.authorize(ctx, s.cfg.Actor, "contributions.maintenance", Record{}); e != nil {
		return snapshot, false, e
	}
	if v.DesiredState == "revoked" && v.AppliedRevision == v.Revision && snapshot.Control != nil && snapshot.Control.ID == v.ID && snapshot.Control.Revision == v.Revision && snapshot.Control.State == "revoked" {
		return snapshot, true, nil
	}
	state := v.DesiredState
	if state == "exiting" {
		state = "draining"
	}
	c := storage.ContributionControl{ID: v.ID, OwnerDomain: OwnerDomain(r.Owner), Revision: v.Revision, ExpectedRevision: snapshot.Revision, State: state, LimitBytes: v.Conditions.LimitBytes, PersonalReserve: v.Conditions.PersonalReserve, Until: v.Conditions.Until}
	// Reuse the permanent revision after a lost response. Storage compares all
	// consent fields; another owner or newer request cannot be overwritten.
	applied, e := s.store.ApplyContribution(ctx, s.cfg.Actor, r.InstanceID, c)
	if e == nil {
		if !s.validSnapshot(r, applied) {
			return applied, false, ErrUnavailable
		}
		return applied, true, nil
	}
	if errors.Is(e, storage.ErrStale) {
		return snapshot, true, errRetryableStale
	}
	if v.DesiredState == "exiting" && errors.Is(e, storage.ErrDenied) && (!snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now())) {
		neverActivated := v.AppliedRevision == 0 && snapshot.Control == nil
		writesStopped := snapshot.Control != nil && (snapshot.Control.State == "draining" || !snapshot.Control.Until.After(s.now()))
		if (neverActivated || writesStopped) && snapshot.RemainingReplicas == 0 && snapshot.UsedBytes == 0 && snapshot.ReservedBytes == 0 {
			return snapshot, true, nil
		}
		return snapshot, true, errPendingExitAuth
	}
	return snapshot, true, storeError(e)
}
