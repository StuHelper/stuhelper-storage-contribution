package contribution

import (
	"context"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Admission policy may be lowered while older bindings remain in the registry.
const registryLimit = 100

type Service struct {
	repo  Repository
	auth  Authorizer
	store Store
	cfg   Config
}

func New(r Repository, a Authorizer, st Store, c Config) (*Service, error) {
	u, e := url.Parse(c.Policy.Terms.URL)
	p := c.Policy
	if r == nil || a == nil || st == nil || !c.Actor.Valid() || c.Clock == nil || e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || !identifier.MatchString(p.Terms.Version) || !digestPattern.MatchString(p.Terms.Digest) || len(p.Adapters) == 0 || len(p.Adapters) > 20 || p.MinBytes < 1 || p.MaxBytes < p.MinBytes || p.MaxBytes > 1<<46 || p.MinTermSeconds < 1 || p.MaxTermSeconds < p.MinTermSeconds || p.MaxTermSeconds > 366*86400 || p.ExitTargetSeconds < 1 || p.ExitTargetSeconds > 366*86400 || p.MaxPerOwner < 1 || p.MaxPerOwner > 100 || c.MaxContributions < p.MaxPerOwner || c.MaxContributions > registryLimit || c.MaxAttempts < 1 || c.MaxAttempts > 10 || c.OperationTimeout < time.Second || c.OperationTimeout > time.Minute || c.Lease < 2*c.OperationTimeout || c.Lease > 10*time.Minute || c.RefreshInterval < time.Second || c.RefreshInterval > time.Hour || time.Duration(p.ObservationMaxAgeSeconds)*time.Second < 2*c.RefreshInterval || p.ObservationMaxAgeSeconds > 3600 {
		return nil, ErrInput
	}
	for _, adapter := range p.Adapters {
		if !identifier.MatchString(adapter) {
			return nil, ErrInput
		}
	}
	c.Policy.Adapters = slices.Clone(p.Adapters)
	return &Service{r, a, st, c}, nil
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
	admin := action == "contributions.operations.read" || action == "contributions.operations.retry"
	if !p.Valid() || (action != "contributions.maintenance" && (p == s.cfg.Actor || (!admin && p != r.Owner))) {
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
func (s *Service) validConditions(c Conditions) bool {
	now := s.now()
	p := s.cfg.Policy
	return c.LimitBytes >= p.MinBytes && c.LimitBytes <= p.MaxBytes && c.PersonalReserve >= 0 && c.PersonalReserve <= 1<<46 && !c.Until.Before(now.Add(time.Duration(p.MinTermSeconds)*time.Second)) && !c.Until.After(now.Add(time.Duration(p.MaxTermSeconds)*time.Second))
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
func (s *Service) emit(tx Transaction, p Principal, kind string, r *Record) error {
	r.EventRevision++
	r.View.UpdatedAt = s.now()
	r.View.DisplayLabel = ""
	e := Event{SpecVersion: "1.0", Source: "stuhelper://storage-contribution", ID: hash([]any{r.View.ID, r.EventRevision}), Type: kind, Subject: r.View.ID, Time: s.now(), DataContentType: "application/json", Data: EventData{r.EventRevision, r.View.Revision, r.View.AppliedRevision, r.View.State}, Actor: p}
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
	return old.Result, true, nil
}

func (s *Service) mutation(ctx context.Context, p Principal, action, id, key string, request any, run func(Transaction, *Record) error) (View, error) {
	var out View
	if !idempotencyKey.MatchString(key) || (id != "" && !contributionID(id)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	replayKey := hash([]any{p, action, id, key})
	payload := requestHash(request, time.UTC)
	err := s.repo.Transaction(ctx, func(tx Transaction) error {
		if e := tx.Lock("replay:" + replayKey); e != nil {
			return e
		}
		r := Record{Owner: p}
		if id != "" {
			var e error
			r, e = tx.Record(id)
			if e != nil {
				return e
			}
		}
		if e := s.authorize(ctx, p, action, r); e != nil {
			return e
		}
		previous, found, e := s.replay(tx, replayKey, request)
		if e != nil {
			return e
		}
		if found {
			out = previous
			return nil
		}
		if e = run(tx, &r); e != nil {
			return e
		}
		if e = s.authorize(ctx, p, action, r); e != nil {
			return e
		}
		if e = s.emit(tx, p, "contribution.requested", &r); e != nil {
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
		return tx.SaveReplay(Replay{replayKey, payload, out, s.now().Add(24 * time.Hour)})
	})
	return out, err
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
		return View{}, e
	}
	var previous View
	var found bool
	e = s.repo.Transaction(ctx, func(tx Transaction) error {
		var err error
		previous, found, err = s.replay(tx, hash([]any{p, action, "", key}), q)
		return err
	})
	if e != nil || found {
		return previous, e
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
		return View{}, storeError(e)
	}
	if snapshot.InstanceID != q.InstanceID {
		return View{}, ErrInput
	}
	if !slices.Contains(s.cfg.Policy.Adapters, snapshot.Adapter) {
		return View{}, detailErr(ErrInput, "instance_not_eligible")
	}
	return s.mutation(ctx, p, "contributions.create", "", key, q, func(tx Transaction, r *Record) error {
		if err := s.validateCreateInput(q); err != nil {
			return err
		}
		if !snapshot.Authorized || !snapshot.AuthorizationExpiresAt.After(s.now()) || snapshot.State != "paused" || snapshot.Control != nil || snapshot.UsedBytes != 0 || snapshot.ReservedBytes != 0 || snapshot.RemainingReplicas != 0 {
			return detailErr(ErrConflict, "instance_not_eligible")
		}
		if e := tx.Lock("registry"); e != nil {
			return e
		}
		total, owned, e := tx.Counts(p)
		if e != nil {
			return e
		}
		if owned >= s.cfg.Policy.MaxPerOwner {
			return detailErr(ErrConflict, "owner_quota_exceeded")
		}
		if total >= s.cfg.MaxContributions {
			return detailErr(ErrConflict, "registry_full")
		}
		stableID := hash([]string{"contribution", q.InstanceID})
		if _, e = tx.Record(stableID); e == nil {
			return detailErr(ErrConflict, "already_bound")
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		r.InstanceID = q.InstanceID
		if hasLabel {
			r.DisplayLabel = label
		}
		// One permanent binding per instance makes late replays safe beyond the
		// response retention window. Reuse needs a separately reviewed flow.
		r.View = View{ID: hash([]string{"contribution", q.InstanceID}), Adapter: snapshot.Adapter, Revision: 1, DesiredState: "active", State: "pending", Conditions: q.Conditions, Consent: s.cfg.Policy.Terms, AcceptedAt: s.now(), CreatedAt: s.now(), UpdatedAt: s.now()}
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
	return s.mutation(ctx, p, "contributions.manage", id, key, q, func(_ Transaction, r *Record) error {
		v := &r.View
		if v.Revision != q.Revision {
			return detailErr(ErrConflict, "revision_conflict")
		}
		if v.State == "exited" {
			return detailErr(ErrConflict, "invalid_state_transition")
		}
		if q.Action != "configure" && q.DisplayLabel != nil {
			return ErrInput
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
			if q.Conditions == nil {
				return ErrInput
			}
			if q.Conditions.LimitBytes < s.cfg.Policy.MinBytes || q.Conditions.LimitBytes > s.cfg.Policy.MaxBytes || q.Conditions.PersonalReserve < 0 || q.Conditions.PersonalReserve > 1<<46 {
				return detailErr(ErrInput, "limit_out_of_range")
			}
			if v.Observation != nil && q.Conditions.LimitBytes < v.Observation.UsedBytes+v.Observation.ReservedBytes {
				return limitBelowOccupiedErr(max(s.cfg.Policy.MinBytes, v.Observation.UsedBytes+v.Observation.ReservedBytes))
			}
			if q.Action == "configure" {
				if q.Consent != nil {
					return ErrInput
				}
				if !q.Conditions.Until.Equal(v.Conditions.Until) || !q.Conditions.Until.After(s.now()) {
					return detailErr(ErrInput, "term_out_of_range")
				}
				if hasLabel {
					r.DisplayLabel = label
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
func (s *Service) observationCurrent(v View) bool {
	o := v.Observation
	now := s.now()
	return o != nil && !o.ObservedAt.After(now.Add(time.Second)) && o.ObservedAt.After(now.Add(-time.Duration(s.cfg.Policy.ObservationMaxAgeSeconds)*time.Second))
}
func (s *Service) capacityValid(v View) bool {
	o := v.Observation
	now := s.now()
	return s.observationCurrent(v) && o.Authorized && o.AuthorizationExpiresAt.After(now) && o.QuotaExpiresAt.After(now)
}
func (s *Service) view(r Record) View {
	v := r.View
	v.DisplayLabel = ""
	if v.ExitInitialReplicas != nil {
		n := *v.ExitInitialReplicas
		v.ExitInitialReplicas = &n
	}
	if v.ExitInitialUsedBytes != nil {
		n := *v.ExitInitialUsedBytes
		v.ExitInitialUsedBytes = &n
	}
	now := s.now()
	if v.DesiredState == "exiting" && v.Reason == "capacity_unknown" {
		v.Reason = ""
	}
	if v.Observation != nil {
		o := *v.Observation
		v.Observation = &o
		if !s.capacityValid(v) || v.State != "active" || v.DesiredState != "active" || !v.Conditions.Until.After(now) {
			o.AvailableBytes = 0
		}
	}
	if (v.DesiredState == "active" || v.DesiredState == "paused") && !v.Conditions.Until.After(now) {
		v.Reason = "consent_expired"
	} else if v.State == "active" {
		switch {
		case !s.observationCurrent(v):
			v.Reason = "observation_stale"
		case !v.Observation.Authorized || !v.Observation.AuthorizationExpiresAt.After(now):
			v.Reason = "authorization_required"
		case !v.Observation.QuotaExpiresAt.After(now):
			v.Reason = "capacity_unknown"
		}
	} else if v.DesiredState == "exiting" && v.State != "exited" && v.ExitTargetAt != nil && !v.ExitTargetAt.After(now) && v.Reason == "" {
		v.Reason = "exit_overdue"
	}
	return v
}
func (s *Service) ownerView(r Record) View {
	v := s.view(r)
	v.DisplayLabel = r.DisplayLabel
	return v
}
func (s *Service) Get(ctx context.Context, p Principal, id string) (View, error) {
	var out View
	if !contributionID(id) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		r, e := tx.Record(id)
		if e != nil {
			return e
		}
		if e = s.authorize(ctx, p, "contributions.read", r); e != nil {
			return e
		}
		out = s.ownerView(r)
		return nil
	})
	return out, e
}
func (s *Service) List(ctx context.Context, p Principal, n int, after string) (Page, error) {
	out := Page{Items: []View{}}
	if n < 1 || n > 100 || (after != "" && !identifier.MatchString(after)) {
		return out, ErrInput
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
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
		for _, r := range rs {
			out.Items = append(out.Items, s.ownerView(r))
		}
		return s.authorize(ctx, p, "contributions.read", Record{Owner: p})
	})
	return out, e
}
func (s *Service) Statistics(ctx context.Context) (Statistics, error) {
	out := Statistics{Status: "current", GeneratedAt: s.now()}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.OperationTimeout)
	defer cancel()
	e := s.repo.Transaction(ctx, func(tx Transaction) error {
		rs, e := tx.Scan(registryLimit, "")
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
			if s.observationCurrent(v) {
				out.FreshObservations++
				out.UsedBytes += v.Observation.UsedBytes
				out.ReservedBytes += v.Observation.ReservedBytes
				out.AvailableBytes += v.Observation.AvailableBytes
			}
		}
		if out.FreshObservations != out.Contributions {
			out.Status = "partial"
		}
		return nil
	})
	return out, e
}
