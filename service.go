package contribution

import (
	"context"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"github.com/StuHelper/stuhelper-storage-contribution/auditquery"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// Admission policy may be lowered while older bindings remain in the registry.
const registryLimit = 100

const maxSafeJSInt int64 = (1 << 53) - 1

type statsCall struct {
	done chan struct{}
	val  Statistics
	err  error
}

// Service manages contribution lifecycle and holds a 1-entry aggregate cache
// for anonymous Statistics (source: contribution.contributions, default TTL 5s,
// invalidated on local mutations, Sweep transitions and RunOne completions).
type Service struct {
	repo           Repository
	auth           Authorizer
	store          Store
	cfg            Config
	statsMu        sync.Mutex
	statsCached    Statistics
	statsExpiresAt time.Time
	statsGen       uint64
	statsInFlight  *statsCall
	auditSeq       atomic.Uint64
}

func New(r Repository, a Authorizer, st Store, c Config) (*Service, error) {
	if c.StatisticsCacheTTL == 0 {
		c.StatisticsCacheTTL = 5 * time.Second
	}
	if c.Policy.RenewalNoticeSeconds == 0 {
		c.Policy.RenewalNoticeSeconds = 7 * 86400
	}
	u, e := url.Parse(c.Policy.Terms.URL)
	p := c.Policy
	if c.ActivationWindow == 0 {
		c.ActivationWindow = 24 * time.Hour
	}
	if c.MaxOwnerActivations == 0 {
		c.MaxOwnerActivations = max(2*p.MaxPerOwner, 4)
	}
	if r == nil || a == nil || st == nil || !c.Actor.Valid() || c.Clock == nil || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !identifier.MatchString(p.Terms.Version) || !digestPattern.MatchString(p.Terms.Digest) || len(p.Adapters) == 0 || len(p.Adapters) > 20 || p.MinBytes < 1 || p.MaxBytes < p.MinBytes || p.MaxBytes > 1<<46 || p.MinTermSeconds < 1 || p.MaxTermSeconds < p.MinTermSeconds || p.MaxTermSeconds > 366*86400 || p.ExitTargetSeconds < 1 || p.ExitTargetSeconds > 366*86400 || p.MaxPerOwner < 1 || p.MaxPerOwner > 100 || c.MaxContributions < p.MaxPerOwner || c.MaxContributions > registryLimit || c.MaxAttempts < 1 || c.MaxAttempts > 10 || c.OperationTimeout < time.Second || c.OperationTimeout > time.Minute || c.Lease < 2*c.OperationTimeout || c.Lease > 10*time.Minute || c.RefreshInterval < time.Second || c.RefreshInterval > time.Hour || time.Duration(p.ObservationMaxAgeSeconds)*time.Second < 2*c.RefreshInterval || p.ObservationMaxAgeSeconds > 3600 || c.StatisticsCacheTTL > time.Minute || p.RenewalNoticeSeconds < 1 || p.RenewalNoticeSeconds > 366*86400 || c.ActivationWindow < time.Minute || c.ActivationWindow > 30*24*time.Hour || c.MaxOwnerActivations < p.MaxPerOwner || c.MaxOwnerActivations > 200 {
		return nil, ErrInput
	}
	for _, adapter := range p.Adapters {
		if !identifier.MatchString(adapter) {
			return nil, ErrInput
		}
	}
	c.Policy.Adapters = slices.Clone(p.Adapters)
	return &Service{repo: r, auth: a, store: st, cfg: c}, nil
}
func (s *Service) invalidateStatistics() {
	s.statsMu.Lock()
	s.statsGen++
	s.statsInFlight = nil
	s.statsExpiresAt = time.Time{}
	s.statsMu.Unlock()
}
func sanitizeDisplayLabel(raw *string) (string, bool, error) {
	if raw == nil {
		return "", false, nil
	}
	if len(*raw) > 256 || !utf8.ValidString(*raw) {
		return "", false, ErrInput
	}
	var b strings.Builder
	for _, ch := range *raw {
		if !unicode.IsControl(ch) {
			b.WriteRune(ch)
		}
	}
	cleaned := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(cleaned) > 32 || len(cleaned) > 128 {
		return "", false, ErrInput
	}
	return cleaned, true, nil
}
func (s *Service) now() time.Time { return s.cfg.Clock().UTC() }
func (s *Service) Policy() Policy { p := s.cfg.Policy; p.Adapters = slices.Clone(p.Adapters); return p }
func (s *Service) authorize(ctx context.Context, p Principal, action string, r Record) error {
	admin := action == "contributions.operations.read" || action == "contributions.operations.retry" || action == "contributions.audit.read"
	system := action == "contributions.maintenance" || action == "contributions.adopt"
	if !p.Valid() || (p == s.cfg.Actor) != system || (!system && !admin && p != r.Owner) {
		return ErrDenied
	}
	if e := s.auth.Authorize(ctx, p, action, Access{r.View.ID, r.Owner}); e != nil {
		if errors.Is(e, ErrDenied) {
			return ErrDenied
		}
		return ErrUnavailable
	}
	return nil
}
func (s *Service) nextAuditID(prefix string, p Principal, action, target string) string {
	return hash([]any{prefix, p, action, target, s.now().UnixNano(), s.auditSeq.Add(1)})
}
func (s *Service) recordDenied(ctx context.Context, p Principal, action, target, school string) {
	if !p.Valid() {
		return
	}
	if school == "" {
		school = p.Issuer
	}
	auditCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.OperationTimeout)
	defer cancel()
	_ = s.repo.Transaction(auditCtx, func(tx Transaction) error {
		return tx.Audit(AuditEntry{
			ID:     s.nextAuditID("denied", p, action, target),
			Actor:  p,
			Action: action,
			Target: target,
			School: school,
			Reason: "permission_denied",
			Result: "denied",
			Time:   s.now(),
		})
	})
}
func (s *Service) validConditions(c Conditions) bool {
	return s.validConditionsWithLimit(c, s.cfg.Policy.MaxBytes)
}
func (s *Service) validConditionsWithLimit(c Conditions, maxBytes int64) bool {
	now := s.now()
	p := s.cfg.Policy
	return c.LimitBytes >= p.MinBytes && c.LimitBytes <= maxBytes && c.PersonalReserve >= 0 && c.PersonalReserve <= 1<<46 && !c.Until.Before(now.Add(time.Duration(p.MinTermSeconds)*time.Second)) && !c.Until.After(now.Add(time.Duration(p.MaxTermSeconds)*time.Second))
}
func (s *Service) contributionLimit(r Record, until time.Time) int64 {
	if r.Adoption != nil && !until.After(r.Adoption.Conditions.Until) {
		return max(s.cfg.Policy.MaxBytes, r.Adoption.Conditions.LimitBytes)
	}
	return s.cfg.Policy.MaxBytes
}
func (s *Service) validateCreateInput(q CreateRequest) error {
	if !s.validConsent(q.Consent) {
		return detailErr(ErrInput, "terms_version_mismatch")
	}
	if q.Conditions.LimitBytes < s.cfg.Policy.MinBytes || q.Conditions.LimitBytes > s.cfg.Policy.MaxBytes || q.Conditions.PersonalReserve < 0 || q.Conditions.PersonalReserve > 1<<46 {
		return detailErr(ErrInput, "limit_out_of_range")
	}
	if !s.validConditions(q.Conditions) {
		return detailErr(ErrInput, "term_out_of_range")
	}
	return nil
}
func (s *Service) validConsent(c Consent) bool {
	return c.Accepted && c.Version == s.cfg.Policy.Terms.Version && c.Digest == s.cfg.Policy.Terms.Digest
}
func (s *Service) emit(ctx context.Context, tx Transaction, p Principal, kind string, warnings []string, r *Record) error {
	r.EventRevision++
	r.View.UpdatedAt = s.now()
	r.View.JobState = ""
	r.View.Attempts = nil
	r.View.MaxAttempts = nil
	r.View.AvailableAt = nil
	r.View.DisplayLabel = ""
	r.View.AccountHint = ""
	r.View.VerifiedActiveSeconds = nil
	r.View.VerifiedAvailableByteHours = nil
	r.View.VerifiedUsedByteHours = nil
	r.View.Warnings = nil
	tp := Traceparent(ctx)
	if tp != "" {
		r.LastTraceparent = tp
	} else {
		tp = r.LastTraceparent
	}
	e := Event{
		SpecVersion:     "1.0",
		Source:          "stuhelper://storage-contribution",
		ID:              hash([]any{r.View.ID, r.EventRevision}),
		Type:            kind,
		Subject:         r.View.ID,
		Time:            s.now(),
		Traceparent:     tp,
		DataContentType: "application/json",
		Data:            EventData{Revision: r.EventRevision, DesiredRevision: r.View.Revision, AppliedRevision: r.View.AppliedRevision, State: r.View.State, Reason: r.View.Reason, Warnings: slices.Clone(warnings)},
		Actor:           p, School: r.Owner.Issuer,
	}
	if err := tx.SaveRecord(*r); err != nil {
		return err
	}
	return tx.Event(e)
}
func (s *Service) enqueue(tx Transaction, r Record) error {
	j, e := tx.Job(r.View.ID)
	if e != nil && !errors.Is(e, ErrNotFound) {
		return e
	}
	j.ID = r.View.ID
	j.Generation++
	j.State = "pending"
	j.Attempts = 0
	j.AvailableAt = s.now()
	j.LeaseUntil = time.Time{}
	j.LeaseOwner = ""
	return tx.SaveJob(j)
}

// Normalize instants for new receipts. Older receipts retain the offset of
// the submitted conditions in their stored result.
func requestHash(request any, zone *time.Location) string {
	switch q := request.(type) {
	case CreateRequest:
		q.Conditions.Until = q.Conditions.Until.In(zone)
		return hash(q)
	case CommandRequest:
		if q.Conditions != nil {
			conditions := *q.Conditions
			conditions.Until = conditions.Until.In(zone)
			q.Conditions = &conditions
		}
		return hash(q)
	}
	return hash(request)
}

func (s *Service) replay(tx Transaction, key string, request any) (View, bool, error) {
	old, err := tx.Replay(key)
	if errors.Is(err, ErrNotFound) {
		return View{}, false, nil
	}
	if err != nil {
		return View{}, false, err
	}
	if !old.ExpiresAt.After(s.now()) {
		return View{}, false, nil
	}
	if old.Hash != requestHash(request, time.UTC) && old.Hash != requestHash(request, old.Result.Conditions.Until.Location()) {
		return View{}, false, detailErr(ErrConflict, "idempotency_mismatch")
	}
	if old.Result.Observation != nil && !old.QuotaReadTimestamp {
		// Older receipts contained the worker poll time. They have no recorded quota read time.
		old.Result.Observation.ObservedAt = nil
	}
	return old.Result, true, nil
}

func recordActivation(existing []time.Time, since, now time.Time) []time.Time {
	out := make([]time.Time, 0, len(existing)+1)
	for _, ts := range existing {
		if ts.After(since) {
			out = append(out, ts)
		}
	}
	return append(out, now)
}
func (s *Service) checkAdmissionBudget(tx Transaction, p Principal, existing []time.Time) ([]time.Time, error) {
	now := s.now()
	since := now.Add(-s.cfg.ActivationWindow)
	total, owned, e := tx.Counts(p)
	if e != nil {
		return nil, e
	}
	if owned >= s.cfg.Policy.MaxPerOwner {
		return nil, detailErr(ErrConflict, "owner_quota_exceeded")
	}
	if total >= s.cfg.MaxContributions {
		return nil, detailErr(ErrConflict, "registry_full")
	}
	recent, e := tx.OwnerActivations(p, since)
	if e != nil {
		return nil, e
	}
	if recent >= s.cfg.MaxOwnerActivations {
		return nil, ErrConflict
	}
	return recordActivation(existing, since, now), nil
}
func (s *Service) mutation(ctx context.Context, p Principal, action, id, key string, request any, run func(Transaction, *Record) error) (View, error) {
	return s.mutationLocked(ctx, p, action, id, key, false, request, run)
}
func (s *Service) mutationLocked(ctx context.Context, p Principal, action, id, key string, lockRegistry bool, request any, run func(Transaction, *Record) error) (View, error) {
	var out View
	if !idempotencyKey.MatchString(key) || (id != "" && !contributionID(id)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	replayKey := hash([]any{p, action, id, key})
	payload := requestHash(request, time.UTC)
	mutated := false
	var accountID string
	var owner Principal
	deniedSchool := ""
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("replay:" + replayKey); e != nil {
			return e
		}
		if lockRegistry {
			if e := tx.Lock("registry"); e != nil {
				return e
			}
		}
		r := Record{Owner: p}
		if id != "" {
			var e error
			r, e = tx.Record(id)
			if e != nil {
				return e
			}
			deniedSchool = r.Owner.Issuer
		}
		if e := s.authorize(ctx, p, action, r); e != nil {
			return e
		}
		previous, found, e := s.replay(tx, replayKey, request)
		if e != nil {
			return e
		}
		if found {
			if create, ok := request.(CreateRequest); ok {
				r.InstanceID = create.InstanceID
			}
			out = previous
			accountID, owner = r.InstanceID, r.Owner
			return nil
		}
		if e = run(tx, &r); e != nil {
			return e
		}
		if e = s.authorize(ctx, p, action, r); e != nil {
			return e
		}
		eventType := "contribution.requested.v1"
		if action == "contributions.operations.retry" {
			eventType = "contribution.operation_retried.v1"
		}
		if action == "contributions.adopt" {
			eventType = "contribution.adoption_requested.v1"
		}
		if e = s.emit(ctx, tx, p, eventType, nil, &r); e != nil {
			return e
		}
		if e = s.enqueue(tx, r); e != nil {
			return e
		}
		if action == "contributions.create" || action == "contributions.manage" {
			out = s.ownerView(r)
		} else {
			out = s.view(r)
		}
		mutated = true
		accountID, owner = r.InstanceID, r.Owner
		return tx.SaveReplay(Replay{
			Key: replayKey, Hash: payload, Result: out, ExpiresAt: s.now().Add(24 * time.Hour),
			QuotaReadTimestamp: true,
		})
	})
	if err == nil && mutated {
		s.invalidateStatistics()
	}
	if errors.Is(err, ErrDenied) {
		target := id
		if target == "" {
			target = "contributions"
		}
		s.recordDenied(ctx, p, action, target, deniedSchool)
	}
	if err == nil && action != "contributions.adopt" {
		out.AccountHint = s.accountHint(ctx, accountID, owner)
	}
	return out, err
}

func (s *Service) accountHint(ctx context.Context, instanceID string, owner Principal) string {
	if instanceID == "" {
		return ""
	}
	return s.store.ContributionAccountHints(ctx, s.cfg.Actor, map[string]string{instanceID: OwnerDomain(owner)})[instanceID]
}

func (s *Service) ownerCapacity(ctx context.Context, p Principal, instanceID string) (storage.OwnerCapacity, error) {
	items, err := s.store.InspectOwnerCapacities(ctx, s.cfg.Actor, p, []string{instanceID})
	if err != nil {
		return storage.OwnerCapacity{}, storeError(err)
	}
	return items[instanceID], nil
}

func validateProviderLimit(capacity storage.OwnerCapacity, c Conditions) error {
	limit, err := capacity.ContributionLimit(c.PersonalReserve)
	if err != nil {
		return storeError(err)
	}
	if c.LimitBytes > limit {
		return detailErr(ErrInput, providerLimitExceeded)
	}
	return nil
}

func (s *Service) Create(ctx context.Context, p Principal, key string, q CreateRequest) (View, error) {
	if !idempotencyKey.MatchString(key) || !identifier.MatchString(q.InstanceID) {
		return View{}, ErrInput
	}
	label, hasLabel, e := sanitizeDisplayLabel(q.DisplayLabel)
	if e != nil {
		return View{}, e
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	const action = "contributions.create"
	if e := s.authorize(ctx, p, action, Record{Owner: p}); e != nil {
		if errors.Is(e, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.create", hash([]string{"contribution", q.InstanceID}), p.Issuer)
		}
		return View{}, e
	}
	var previous View
	var found bool
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		previous, found, err = s.replay(tx, hash([]any{p, action, "", key}), q)
		return err
	})
	if e != nil {
		return View{}, e
	}
	if found {
		previous.AccountHint = s.accountHint(ctx, q.InstanceID, p)
		return previous, nil
	}
	if err := s.validateCreateInput(q); err != nil {
		return View{}, err
	}
	// Verify ownership outside the database transaction. The mutation rechecks
	// current permission and the receipt under the replay lock before writing.
	snapshot, e := s.store.InspectContribution(ctx, s.cfg.Actor, q.InstanceID, OwnerDomain(p))
	if errors.Is(e, storage.ErrDenied) || errors.Is(e, storage.ErrNotFound) {
		return View{}, ErrNotFound
	}
	if e != nil {
		mapped := storeError(e)
		if errors.Is(mapped, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.create", hash([]string{"contribution", q.InstanceID}), p.Issuer)
		}
		return View{}, mapped
	}
	if snapshot.InstanceID != q.InstanceID {
		return View{}, ErrInput
	}
	if !slices.Contains(s.cfg.Policy.Adapters, snapshot.Adapter) {
		return View{}, detailErr(ErrInput, "instance_not_eligible")
	}
	capacity, e := s.ownerCapacity(ctx, p, q.InstanceID)
	if e != nil {
		return View{}, e
	}
	return s.mutationLocked(ctx, p, "contributions.create", "", key, true, q, func(tx Transaction, r *Record) error {
		if err := s.validateCreateInput(q); err != nil {
			return err
		}
		if !snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now()) || snapshot.State != "paused" || snapshot.Control != nil || snapshot.UsedBytes != 0 || snapshot.ReservedBytes != 0 || snapshot.RemainingReplicas != 0 {
			return detailErr(ErrConflict, "instance_not_eligible")
		}
		stableID := hash([]string{"contribution", q.InstanceID})
		if _, e = tx.Record(stableID); e == nil {
			return detailErr(ErrConflict, "already_bound")
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		if e := validateProviderLimit(capacity, q.Conditions); e != nil {
			return e
		}
		activations, e := s.checkAdmissionBudget(tx, p, nil)
		if e != nil {
			return e
		}
		r.InstanceID = q.InstanceID
		r.Activations = activations
		if hasLabel {
			r.DisplayLabel = label
		}
		// One permanent binding per instance makes late replays safe beyond the
		// response retention window; reopen reuses the same binding ID.
		r.View = View{ID: stableID, Adapter: snapshot.Adapter, Revision: 1, DesiredState: "active", State: "pending", Conditions: q.Conditions, Consent: s.cfg.Policy.Terms, AcceptedAt: s.now(), CreatedAt: s.now(), UpdatedAt: s.now()}
		return nil
	})
}
func (s *Service) reopen(ctx context.Context, p Principal, id, key string, q CommandRequest) (View, error) {
	if !identifier.MatchString(key) || !identifier.MatchString(id) {
		return View{}, ErrInput
	}
	replayKey := hash([]any{p, "contributions.manage", id, key})

	var instanceID string
	var replayed *View
	precheck, cancelPrecheck := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	err := s.repo.Transaction(precheck, func(tx Transaction) error {
		if e := tx.Lock("replay:" + replayKey); e != nil {
			return e
		}
		r, e := tx.Record(id)
		if e != nil {
			return e
		}
		if e = s.authorize(precheck, p, "contributions.manage", r); e != nil {
			return e
		}
		instanceID = r.InstanceID
		previous, hit, err := s.replay(tx, replayKey, q)
		if err != nil {
			return err
		}
		if hit {
			replayed = &previous
			return nil
		}
		if r.View.Revision != q.Revision || r.View.State != "exited" {
			return ErrConflict
		}
		if q.Conditions == nil || q.Consent == nil || !s.validConditions(*q.Conditions) || !s.validConsent(*q.Consent) {
			return ErrInput
		}
		return nil
	})
	cancelPrecheck()
	if err != nil {
		return View{}, err
	}
	lookup, cancelLookup := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancelLookup()
	if replayed != nil {
		replayed.AccountHint = s.accountHint(lookup, instanceID, p)
		return *replayed, nil
	}
	snapshot, e := s.store.InspectContribution(lookup, s.cfg.Actor, instanceID, OwnerDomain(p))
	if e != nil {
		return View{}, storeError(e)
	}
	if snapshot.InstanceID != instanceID || !slices.Contains(s.cfg.Policy.Adapters, snapshot.Adapter) {
		return View{}, ErrInput
	}
	capacity, e := s.ownerCapacity(lookup, p, instanceID)
	if e != nil {
		return View{}, e
	}
	return s.mutationLocked(ctx, p, "contributions.manage", id, key, true, q, func(tx Transaction, r *Record) error {
		v := &r.View
		if v.Revision != q.Revision || v.State != "exited" {
			return ErrConflict
		}
		if q.Conditions == nil || q.Consent == nil || !s.validConditions(*q.Conditions) || !s.validConsent(*q.Consent) {
			return ErrInput
		}
		if !snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now()) || (snapshot.State != "paused" && snapshot.State != "draining") || (snapshot.Control != nil && (snapshot.Control.ID != v.ID || snapshot.Control.State == "revoked")) || snapshot.UsedBytes != 0 || snapshot.ReservedBytes != 0 || snapshot.RemainingReplicas != 0 {
			return ErrConflict
		}
		if e := validateProviderLimit(capacity, *q.Conditions); e != nil {
			return e
		}
		activations, e := s.checkAdmissionBudget(tx, p, r.Activations)
		if e != nil {
			return e
		}
		r.Activations = activations
		v.Adapter = snapshot.Adapter
		v.DesiredState = "active"
		v.Conditions = *q.Conditions
		v.Consent = s.cfg.Policy.Terms
		v.AcceptedAt = s.now()
		v.ExitRequestedAt = nil
		v.ExitTargetAt = nil
		v.ExitInitialReplicas = nil
		v.ExitInitialUsedBytes = nil
		r.ConsentWarnedUntil = nil
		r.AuthWarnedUntil = nil
		v.Revision++
		v.State = "pending"
		v.Reason = ""
		return nil
	})
}
func (s *Service) Command(ctx context.Context, p Principal, id, key string, q CommandRequest) (View, error) {
	if q.Revision < 1 || !contributionID(id) {
		return View{}, ErrInput
	}
	label, hasLabel, e := sanitizeDisplayLabel(q.DisplayLabel)
	if e != nil {
		return View{}, e
	}
	if q.Action != "configure" && hasLabel {
		return View{}, ErrInput
	}
	if q.Action == "reopen" {
		return s.reopen(ctx, p, id, key, q)
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	return s.mutation(ctx, p, "contributions.manage", id, key, q, func(_ Transaction, r *Record) error {
		v := &r.View
		if r.Adoption != nil && v.AppliedRevision == 0 {
			return detailErr(ErrConflict, "invalid_state_transition")
		}
		if v.Revision != q.Revision {
			return detailErr(ErrConflict, "revision_conflict")
		}
		if v.State == "exited" {
			return detailErr(ErrConflict, "invalid_state_transition")
		}
		if q.Action != "configure" && q.Action != "renew" && (q.Conditions != nil || q.Consent != nil) {
			return ErrInput
		}
		switch q.Action {
		case "pause":
			if v.DesiredState != "active" {
				return detailErr(ErrConflict, "invalid_state_transition")
			}
			v.DesiredState = "paused"
		case "resume":
			if v.DesiredState != "paused" || !v.Conditions.Until.After(s.now()) {
				return detailErr(ErrConflict, "invalid_state_transition")
			}
			v.DesiredState = "active"
		case "exit":
			if v.DesiredState != "active" && v.DesiredState != "paused" {
				return detailErr(ErrConflict, "invalid_state_transition")
			}
			s.exit(v)
		case "revoke":
			if v.DesiredState == "revoked" {
				return detailErr(ErrConflict, "invalid_state_transition")
			}
			v.DesiredState = "revoked"
		case "retry":
			if v.State != "blocked" {
				return detailErr(ErrConflict, "invalid_state_transition")
			}
		case "configure", "renew":
			if v.DesiredState != "active" && v.DesiredState != "paused" {
				return detailErr(ErrConflict, "invalid_state_transition")
			}
			if q.Action == "configure" {
				if q.Consent != nil || (q.Conditions == nil && !hasLabel) {
					return ErrInput
				}
				if hasLabel {
					r.DisplayLabel = label
				}
				if q.Conditions == nil {
					break
				}
			}
			if q.Conditions == nil {
				return ErrInput
			}
			if q.Conditions.LimitBytes < s.cfg.Policy.MinBytes || q.Conditions.LimitBytes > s.contributionLimit(*r, q.Conditions.Until) || q.Conditions.PersonalReserve < 0 || q.Conditions.PersonalReserve > 1<<46 {
				return detailErr(ErrInput, "limit_out_of_range")
			}
			if v.Observation != nil && q.Conditions.LimitBytes < v.Observation.UsedBytes+v.Observation.ReservedBytes {
				return limitBelowOccupiedErr(max(s.cfg.Policy.MinBytes, v.Observation.UsedBytes+v.Observation.ReservedBytes))
			}
			if q.Action == "configure" {
				if !q.Conditions.Until.Equal(v.Conditions.Until) || !q.Conditions.Until.After(s.now()) {
					return detailErr(ErrInput, "term_out_of_range")
				}
			} else {
				if q.Consent == nil || !s.validConsent(*q.Consent) {
					return detailErr(ErrInput, "terms_version_mismatch")
				}
				if !s.validConditions(*q.Conditions) || !q.Conditions.Until.After(v.Conditions.Until) {
					return detailErr(ErrInput, "term_out_of_range")
				}
				v.Consent = s.cfg.Policy.Terms
				v.AcceptedAt = s.now()
			}
			if storage.ContributionConditionsExpand(v.Conditions.LimitBytes, v.Conditions.PersonalReserve, q.Conditions.LimitBytes, q.Conditions.PersonalReserve) {
				capacity, err := s.ownerCapacity(ctx, p, r.InstanceID)
				if err != nil {
					return err
				}
				if err = validateProviderLimit(capacity, *q.Conditions); err != nil {
					return err
				}
			}
			v.Conditions = *q.Conditions
		default:
			return ErrInput
		}
		v.Revision++
		v.State = "pending"
		v.Reason = ""
		return nil
	})
}
func (s *Service) exit(v *View) {
	v.DesiredState = "exiting"
	now := s.now()
	target := now.Add(time.Duration(s.cfg.Policy.ExitTargetSeconds) * time.Second)
	v.ExitRequestedAt = &now
	v.ExitTargetAt = &target
	if v.Observation != nil && v.ExitInitialReplicas == nil {
		replicas := v.Observation.RemainingReplicas
		used := v.Observation.UsedBytes
		v.ExitInitialReplicas = &replicas
		v.ExitInitialUsedBytes = &used
	}
}
func (r Record) snapshotAt() time.Time {
	if r.SnapshotAt.IsZero() && r.View.Observation != nil && r.View.Observation.ObservedAt != nil {
		// Before quota timestamps were stored, observed_at held the worker poll time.
		return *r.View.Observation.ObservedAt
	}
	return r.SnapshotAt
}
func (s *Service) observationCurrent(r Record) bool {
	at := r.snapshotAt()
	now := s.now()
	return r.View.Observation != nil && !at.After(now.Add(time.Second)) && at.After(now.Add(-time.Duration(s.cfg.Policy.ObservationMaxAgeSeconds)*time.Second))
}
func capacityReason(status string) string {
	switch status {
	case storage.CapacityExpired:
		return "capacity_expired"
	case storage.CapacityReadFailed:
		return "capacity_read_failed"
	case storage.CapacityNotRead:
		return "capacity_unknown"
	default:
		return ""
	}
}
func isCapacityReason(reason string) bool {
	return reason == "capacity_unknown" || reason == "capacity_read_failed" || reason == "capacity_expired"
}
func observationCapacityReason(o *Observation, status string, now time.Time) string {
	if reason := capacityReason(status); reason != "" {
		return reason
	}
	if !o.QuotaExpiresAt.After(now) {
		if o.ObservedAt == nil {
			return "capacity_unknown"
		}
		return "capacity_expired"
	}
	return ""
}
func clampSafeJS(v int64) int64 {
	if v < 0 {
		return 0
	}
	if v > maxSafeJSInt {
		return maxSafeJSInt
	}
	return v
}
func (s *Service) warnings(v View) []string {
	if v.State == "exited" || v.State == "revoked" {
		return nil
	}
	now := s.now()
	deadline := now.Add(time.Duration(s.cfg.Policy.RenewalNoticeSeconds) * time.Second)
	var out []string
	if (v.DesiredState == "active" || v.DesiredState == "paused") && v.Conditions.Until.After(now) && !v.Conditions.Until.After(deadline) {
		out = append(out, "consent_expiring_soon")
	}
	if (v.DesiredState == "active" || v.DesiredState == "paused" || v.DesiredState == "exiting") && v.Observation != nil && v.Observation.Authorized && v.Observation.AuthorizationExpiresAt.After(now) && !v.Observation.AuthorizationExpiresAt.After(deadline) {
		out = append(out, "authorization_expiring_soon")
	}
	return out
}
func (s *Service) view(r Record) View {
	v := r.View
	v.DisplayLabel = ""
	v.AccountHint = ""
	if v.ExitInitialReplicas != nil {
		n := *v.ExitInitialReplicas
		v.ExitInitialReplicas = &n
	}
	if v.ExitInitialUsedBytes != nil {
		n := *v.ExitInitialUsedBytes
		v.ExitInitialUsedBytes = &n
	}
	now := s.now()
	if v.DesiredState == "exiting" && isCapacityReason(v.Reason) {
		v.Reason = ""
	}
	v.VerifiedActiveSeconds = nil
	v.VerifiedAvailableByteHours = nil
	v.VerifiedUsedByteHours = nil
	observationCurrent := s.observationCurrent(r)
	quotaReason := ""
	if v.Observation != nil {
		o := *v.Observation
		if r.SnapshotAt.IsZero() {
			o.ObservedAt = nil
		}
		quotaReason = observationCapacityReason(&o, r.CapacityStatus, now)
		v.Observation = &o
		if !observationCurrent || !o.Authorized || !o.AuthorizationExpiresAt.After(now) || !o.QuotaExpiresAt.After(now) ||
			v.State != "active" || v.DesiredState != "active" || !v.Conditions.Until.After(now) {
			o.AvailableBytes = 0
		}
	}
	if (v.DesiredState == "active" || v.DesiredState == "paused") && !v.Conditions.Until.After(now) {
		v.Reason = "consent_expired"
	} else if v.State == "active" {
		switch {
		case !observationCurrent:
			v.Reason = "observation_stale"
		case !v.Observation.Authorized || !v.Observation.AuthorizationExpiresAt.After(now):
			v.Reason = "authorization_required"
		case quotaReason != "":
			v.Reason = quotaReason
		}
	} else if v.DesiredState == "exiting" && v.State != "exited" && v.ExitTargetAt != nil && !v.ExitTargetAt.After(now) && v.Reason == "" {
		v.Reason = "exit_overdue"
	}
	v.Warnings = s.warnings(v)
	return v
}
func (s *Service) ownerView(r Record) View {
	v := s.view(r)
	v.DisplayLabel = r.DisplayLabel
	activeSecs := clampSafeJS(r.VerifiedActiveSeconds)
	availHours := clampSafeJS(r.VerifiedAvailableByteHours)
	usedHours := clampSafeJS(r.VerifiedUsedByteHours)
	v.VerifiedActiveSeconds = &activeSecs
	v.VerifiedAvailableByteHours = &availHours
	v.VerifiedUsedByteHours = &usedHours
	return v
}
func ownerCapacityView(v View, capacity storage.OwnerCapacity) OwnerView {
	provider := capacity.ProviderCapacity
	if provider.Status == "" {
		provider.Status = storage.CapacityNotRead
	} else if v.Observation != nil && v.State == "active" && v.DesiredState == "active" &&
		v.AppliedRevision == v.Revision && capacity.ControlRevision == v.AppliedRevision &&
		(v.Reason == "" || isCapacityReason(v.Reason)) {
		v.Reason = capacityReason(provider.Status)
		switch capacity.HealthReason {
		case "authorization_revoked", "authorization_expired":
			v.Reason = "authorization_required"
		case "writes_disabled":
			v.Reason = "storage_writes_disabled"
		}
		v.Observation.ObservedAt = provider.ObservedAt
		v.Observation.QuotaExpiresAt = capacity.QuotaExpiresAt
		v.Observation.AvailableBytes = capacity.AvailableBytes
		v.Observation.UsedBytes = capacity.UsedBytes
		v.Observation.ReservedBytes = capacity.ReservedBytes
	}
	return OwnerView{View: v, ProviderCapacity: provider}
}
func (s *Service) Get(ctx context.Context, p Principal, id string) (OwnerView, error) {
	if !contributionID(id) {
		return OwnerView{}, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	var r Record
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		var e error
		r, e = tx.Record(id)
		if e != nil {
			return e
		}
		return s.authorize(ctx, p, "contributions.read", r)
	})
	if e == nil {
		capacity, err := s.ownerCapacity(ctx, p, r.InstanceID)
		if err != nil {
			return OwnerView{}, err
		}
		view := s.ownerView(r)
		view.AccountHint = s.accountHint(ctx, r.InstanceID, p)
		e = s.authorize(ctx, p, "contributions.read", r)
		if e == nil {
			return ownerCapacityView(view, capacity), nil
		}
	}
	if errors.Is(e, ErrDenied) {
		s.recordDenied(ctx, p, "contributions.read", id, r.Owner.Issuer)
	}
	return OwnerView{}, e
}
func (s *Service) List(ctx context.Context, p Principal, n int, after string) (OwnerPage, error) {
	out := OwnerPage{Items: []OwnerView{}}
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	var records []Record
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
			return e
		}
		rs, e := tx.List(p, n+1, after)
		if e != nil {
			return e
		}
		if len(rs) > n {
			rs = rs[:n]
			out.NextCursor = rs[n-1].View.ID
		}
		records = rs
		return nil
	})
	if e != nil {
		if errors.Is(e, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.read", "contributions", p.Issuer)
		}
		return OwnerPage{}, e
	}
	ids := make([]string, 0, len(records))
	owners := make(map[string]string, len(records))
	owner := OwnerDomain(p)
	for _, r := range records {
		ids = append(ids, r.InstanceID)
		owners[r.InstanceID] = owner
	}
	capacities, e := s.store.InspectOwnerCapacities(ctx, s.cfg.Actor, p, ids)
	if e != nil {
		return OwnerPage{}, storeError(e)
	}
	hints := s.store.ContributionAccountHints(ctx, s.cfg.Actor, owners)
	if e = s.authorize(ctx, p, "contributions.read", Record{Owner: p}); e != nil {
		if errors.Is(e, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.read", "contributions", p.Issuer)
		}
		return OwnerPage{}, e
	}
	for _, r := range records {
		view := s.ownerView(r)
		view.AccountHint = hints[r.InstanceID]
		out.Items = append(out.Items, ownerCapacityView(view, capacities[r.InstanceID]))
	}
	return out, nil
}
func (s *Service) ReadAudit(ctx context.Context, p Principal, q auditquery.Request) (auditquery.Batch, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	if e := s.authorize(ctx, p, "contributions.audit.read", Record{}); e != nil {
		if errors.Is(e, ErrDenied) {
			s.recordDenied(ctx, p, "contributions.audit.read", "audit", p.Issuer)
		}
		return auditquery.Batch{}, e
	}
	reader, ok := s.repo.(auditquery.Reader)
	if !ok {
		return auditquery.Batch{}, ErrUnavailable
	}
	batch, err := reader.ReadAudit(ctx, q)
	if err != nil {
		if errors.Is(err, auditquery.ErrInvalid) {
			return auditquery.Batch{}, ErrInput
		}
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return auditquery.Batch{}, err
		}
		return auditquery.Batch{}, ErrUnavailable
	}
	return batch, nil
}
func (s *Service) Statistics(ctx context.Context) (Statistics, error) {
	if err := ctx.Err(); err != nil {
		return Statistics{}, err
	}
	s.statsMu.Lock()
	if s.cfg.StatisticsCacheTTL > 0 && s.now().Before(s.statsExpiresAt) {
		cached := s.statsCached
		s.statsMu.Unlock()
		return cached, nil
	}
	if call := s.statsInFlight; call != nil {
		s.statsMu.Unlock()
		select {
		case <-call.done:
			return call.val, call.err
		case <-ctx.Done():
			return Statistics{}, ctx.Err()
		}
	}
	call := &statsCall{done: make(chan struct{})}
	gen := s.statsGen
	s.statsInFlight = call
	s.statsMu.Unlock()

	computeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.cfg.OperationTimeout)
	val, err := s.computeStatistics(computeCtx)
	cancel()

	s.statsMu.Lock()
	call.val, call.err = val, err
	if err == nil && s.cfg.StatisticsCacheTTL > 0 && s.statsGen == gen {
		s.statsCached = val
		s.statsExpiresAt = s.now().Add(s.cfg.StatisticsCacheTTL)
	}
	if s.statsInFlight == call {
		s.statsInFlight = nil
	}
	close(call.done)
	s.statsMu.Unlock()

	if ctx.Err() != nil {
		return Statistics{}, ctx.Err()
	}
	return val, err
}
func (s *Service) computeStatistics(ctx context.Context) (Statistics, error) {
	out := Statistics{Status: "current", GeneratedAt: s.now()}
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		cursor := ""
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			rs, e := tx.Scan(registryLimit, cursor)
			if e != nil {
				return e
			}
			for _, r := range rs {
				v := s.view(r)
				if v.State == "exited" || (v.State == "revoked" && v.Reason == "" && v.Observation != nil && v.Observation.RemainingReplicas == 0 && v.Observation.UsedBytes == 0 && v.Observation.ReservedBytes == 0) {
					continue
				}
				out.Contributions++
				if v.DesiredState == "active" || v.DesiredState == "paused" {
					out.DeclaredBytes += v.Conditions.LimitBytes
				}
				if s.observationCurrent(r) {
					out.FreshObservations++
					out.UsedBytes += v.Observation.UsedBytes
					out.ReservedBytes += v.Observation.ReservedBytes
					out.AvailableBytes += v.Observation.AvailableBytes
				}
			}
			if len(rs) < registryLimit {
				break
			}
			next := rs[len(rs)-1].View.ID
			if next <= cursor {
				return ErrUnavailable
			}
			cursor = next
		}
		if out.FreshObservations != out.Contributions {
			out.Status = "partial"
		}
		return nil
	})
	return out, e
}

// UnsettledOwnerClosures excludes only exits and confirmed revocations. Missing
// job state and an unacknowledged revision remain visible to the closing host.
func (s *Service) UnsettledOwnerClosures(ctx context.Context, owner Principal, limit int) ([]View, error) {
	if !owner.Valid() || limit < 1 || limit > 100 {
		return nil, ErrInput
	}
	var views []View
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if err := s.authorize(ctx, owner, "contributions.manage", Record{Owner: owner}); err != nil {
			return err
		}
		records, err := tx.UnsettledOwnerClosures(owner, limit)
		if err != nil {
			return err
		}
		for _, record := range records {
			views = append(views, record.View)
		}
		return nil
	})
	return views, err
}
