// Package contribution manages voluntary storage consent without holding provider credentials.
package contribution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	storage "github.com/StuHelper/stuhelper-storage"
	"regexp"
	"time"
)

var (
	ErrInput       = errors.New("contribution_invalid_input")
	ErrDenied      = errors.New("contribution_permission_denied")
	ErrNotFound    = errors.New("contribution_not_found")
	ErrConflict    = errors.New("contribution_conflict")
	ErrUnavailable = errors.New("contribution_unavailable")
)

// DetailError preserves the base sentinel error for errors.Is while providing a
// closed machine-readable detail code and optional numeric threshold for HTTP/SDK.
type DetailError struct {
	Base             error
	DetailCode       string
	MinRequiredBytes *int64
}

func (e *DetailError) Error() string { return e.Base.Error() }
func (e *DetailError) Unwrap() error { return e.Base }

func detailErr(base error, code string) error {
	return &DetailError{Base: base, DetailCode: code}
}
func limitBelowOccupiedErr(minBytes int64) error {
	v := minBytes
	return &DetailError{Base: ErrConflict, DetailCode: "limit_below_occupied", MinRequiredBytes: &v}
}

const OutboxChannel = "contribution_outbox"
const providerLimitExceeded = "limit_exceeds_provider_capacity"

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)
var idempotencyKey = regexp.MustCompile(`^[ -~]{1,128}$`)

func contributionID(id string) bool {
	switch id {
	case "policy", "options", "operations", "statistics":
		return false
	}
	return identifier.MatchString(id)
}

var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var traceparentPattern = regexp.MustCompile(`^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$`)

type traceparentKey struct{}

// ValidTraceparent checks W3C Trace Context v00 format and rejects all-zero IDs.
func ValidTraceparent(v string) bool {
	return traceparentPattern.MatchString(v) && v[3:35] != "00000000000000000000000000000000" && v[36:52] != "0000000000000000"
}
func WithTraceparent(ctx context.Context, v string) context.Context {
	if !ValidTraceparent(v) {
		return ctx
	}
	return context.WithValue(ctx, traceparentKey{}, v)
}
func Traceparent(ctx context.Context) string {
	v, _ := ctx.Value(traceparentKey{}).(string)
	return v
}

type Principal = storage.Principal
type Access struct {
	ID    string
	Owner Principal
}
type Authorizer interface {
	Authorize(context.Context, Principal, string, Access) error
}

// OperationReadAuthorizer checks list permission and all supplied records against
// one current permission snapshot. Decisions correspond to targets in order.
type OperationReadAuthorizer interface {
	AuthorizeOperationReads(context.Context, Principal, []Access) ([]bool, error)
}

// Store exposes only the provider-independent contribution control boundary.
type Store interface {
	ListContributionCandidates(context.Context, Principal, string, int, string) (storage.ContributionCandidates, error)
	InspectContribution(context.Context, Principal, string, string) (storage.ContributionSnapshot, error)
	InspectOwnerCapacities(context.Context, Principal, Principal, []string) (map[string]storage.OwnerCapacity, error)
	ApplyContribution(context.Context, Principal, string, storage.ContributionControl) (storage.ContributionSnapshot, error)
	ContributionAccountHints(context.Context, Principal, map[string]string) map[string]string
}
type Terms struct {
	Version string `json:"version"`
	Digest  string `json:"digest"`
	URL     string `json:"url"`
}
type Consent struct {
	Accepted bool   `json:"accepted"`
	Version  string `json:"version"`
	Digest   string `json:"digest"`
}
type Conditions struct {
	LimitBytes      int64     `json:"limit_bytes"`
	PersonalReserve int64     `json:"personal_reserve"`
	Until           time.Time `json:"until"`
}
type Policy struct {
	Terms                    Terms    `json:"terms"`
	Adapters                 []string `json:"adapters"`
	MinBytes                 int64    `json:"min_bytes"`
	MaxBytes                 int64    `json:"max_bytes"`
	MinTermSeconds           int64    `json:"min_term_seconds"`
	MaxTermSeconds           int64    `json:"max_term_seconds"`
	ExitTargetSeconds        int64    `json:"exit_target_seconds"`
	MaxPerOwner              int      `json:"max_per_owner"`
	ObservationMaxAgeSeconds int64    `json:"observation_max_age_seconds"`
	RenewalNoticeSeconds     int64    `json:"renewal_notice_seconds"`
}
type Config struct {
	Policy              Policy
	Actor               Principal
	Clock               func() time.Time
	OperationTimeout    time.Duration
	RefreshInterval     time.Duration
	Lease               time.Duration
	StatisticsCacheTTL  time.Duration
	MaxAttempts         int
	MaxContributions    int
	ActivationWindow    time.Duration
	MaxOwnerActivations int
}
type CreateRequest struct {
	InstanceID   string     `json:"instance_id"`
	DisplayLabel *string    `json:"display_label,omitempty"`
	Conditions   Conditions `json:"conditions"`
	Consent      Consent    `json:"consent"`
}
type CommandRequest struct {
	Revision     int64       `json:"revision"`
	Action       string      `json:"action"`
	DisplayLabel *string     `json:"display_label,omitempty"`
	Conditions   *Conditions `json:"conditions,omitempty"`
	Consent      *Consent    `json:"consent,omitempty"`
}
type Observation struct {
	ObservedAt             *time.Time `json:"observed_at"`
	AuthorizationExpiresAt time.Time  `json:"authorization_expires_at"`
	QuotaExpiresAt         time.Time  `json:"quota_expires_at"`
	Authorized             bool       `json:"authorized"`
	UsedBytes              int64      `json:"used_bytes"`
	ReservedBytes          int64      `json:"reserved_bytes"`
	AvailableBytes         int64      `json:"available_bytes"`
	RemainingReplicas      int64      `json:"remaining_replicas"`
}

// View deliberately omits the principal, provider instance and all custody details.
type View struct {
	ID                         string       `json:"id"`
	Adapter                    string       `json:"adapter"`
	AccountHint                string       `json:"account_hint,omitempty"`
	Revision                   int64        `json:"revision"`
	AppliedRevision            int64        `json:"applied_revision"`
	DesiredState               string       `json:"desired_state"`
	State                      string       `json:"state"`
	Reason                     string       `json:"reason"`
	Conditions                 Conditions   `json:"conditions"`
	Consent                    Terms        `json:"consent"`
	AcceptedAt                 time.Time    `json:"accepted_at"`
	CreatedAt                  time.Time    `json:"created_at"`
	UpdatedAt                  time.Time    `json:"updated_at"`
	ExitRequestedAt            *time.Time   `json:"exit_requested_at,omitempty"`
	ExitTargetAt               *time.Time   `json:"exit_target_at,omitempty"`
	DisplayLabel               string       `json:"display_label,omitempty"`
	ExitInitialReplicas        *int64       `json:"exit_initial_replicas,omitempty"`
	ExitInitialUsedBytes       *int64       `json:"exit_initial_used_bytes,omitempty"`
	Observation                *Observation `json:"observation,omitempty"`
	VerifiedActiveSeconds      *int64       `json:"verified_active_seconds,omitempty"`
	VerifiedAvailableByteHours *int64       `json:"verified_available_byte_hours,omitempty"`
	VerifiedUsedByteHours      *int64       `json:"verified_used_byte_hours,omitempty"`
	Warnings                   []string     `json:"warnings,omitempty"`
	JobState                   string       `json:"job_state,omitempty"`
	Attempts                   *int         `json:"attempts,omitempty"`
	MaxAttempts                *int         `json:"max_attempts,omitempty"`
	AvailableAt                *time.Time   `json:"available_at,omitempty"`
}
type OperationsFilter struct {
	Limit   int
	After   string
	State   string
	Reason  string
	Adapter string
}
type MetricsSnapshot struct {
	ByState            map[string]int `json:"by_state"`
	ByReason           map[string]int `json:"by_reason"`
	ByJobState         map[string]int `json:"by_job_state"`
	ExitOverdue        int            `json:"exit_overdue"`
	CleanupUnconfirmed int            `json:"cleanup_unconfirmed"`
	PendingOutbox      int            `json:"pending_outbox"`
	GeneratedAt        time.Time      `json:"generated_at"`
}
type Page struct {
	Items      []View `json:"items"`
	NextCursor string `json:"next_cursor"`
}

// OwnerView includes the current provider quota only in the owner's read path.
type OwnerView struct {
	View
	ProviderCapacity storage.ProviderCapacity `json:"provider_capacity"`
}
type OwnerPage struct {
	Items      []OwnerView `json:"items"`
	NextCursor string      `json:"next_cursor"`
}

type Candidate struct {
	storage.ContributionCandidate
	ProviderCapacity      storage.ProviderCapacity `json:"provider_capacity"`
	SafetyMarginBytes     int64                    `json:"safety_margin_bytes"`
	MaxContributableBytes *int64                   `json:"max_contributable_bytes"`
}
type Candidates struct {
	Items      []Candidate `json:"items"`
	NextCursor string      `json:"next_cursor"`
}
type Statistics struct {
	DeclaredBytes     int64     `json:"declared_bytes"`
	AvailableBytes    int64     `json:"available_bytes"`
	UsedBytes         int64     `json:"used_bytes"`
	ReservedBytes     int64     `json:"reserved_bytes"`
	Contributions     int       `json:"contributions"`
	FreshObservations int       `json:"fresh_observations"`
	Status            string    `json:"status"`
	GeneratedAt       time.Time `json:"generated_at"`
}

// Record and Job belong to this module's repository; they are never HTTP responses.
type Record struct {
	View                          View
	Owner                         Principal
	InstanceID                    string
	SnapshotAt                    time.Time        `json:"SnapshotAt,omitzero"`
	CapacityStatus                string           `json:"CapacityStatus,omitempty"`
	Adoption                      *AdoptionRequest `json:"Adoption,omitempty"`
	EventRevision                 int64
	DisplayLabel                  string      `json:"DisplayLabel,omitempty"`
	VerifiedActiveSeconds         int64       `json:"VerifiedActiveSeconds,omitempty"`
	VerifiedAvailableByteHours    int64       `json:"VerifiedAvailableByteHours,omitempty"`
	VerifiedAvailableRemByteSecs  uint64      `json:"VerifiedAvailableRemByteSecs,omitempty"`
	VerifiedUsedByteHours         int64       `json:"VerifiedUsedByteHours,omitempty"`
	VerifiedUsedRemByteSecs       uint64      `json:"VerifiedUsedRemByteSecs,omitempty"`
	VerifiedActiveNanos           uint64      `json:"VerifiedActiveNanos,omitempty"`
	VerifiedAvailableRemByteNanos uint64      `json:"VerifiedAvailableRemByteNanos,omitempty"`
	VerifiedUsedRemByteNanos      uint64      `json:"VerifiedUsedRemByteNanos,omitempty"`
	ConsentWarnedUntil            *time.Time  `json:"ConsentWarnedUntil,omitempty"`
	AuthWarnedUntil               *time.Time  `json:"AuthWarnedUntil,omitempty"`
	LastTraceparent               string      `json:"LastTraceparent,omitempty"`
	Activations                   []time.Time `json:"Activations,omitempty"`
}
type Job struct {
	ID          string
	State       string
	Generation  int64
	LeaseOwner  string
	LeaseUntil  time.Time
	AvailableAt time.Time
	Attempts    int
}
type Replay struct {
	Key, Hash          string
	Result             View
	ExpiresAt          time.Time
	QuotaReadTimestamp bool `json:"QuotaReadTimestamp,omitempty"`
}
type Event struct {
	SpecVersion     string    `json:"specversion"`
	Source          string    `json:"source"`
	ID              string    `json:"id"`
	Type            string    `json:"type"`
	Subject         string    `json:"subject"`
	Time            time.Time `json:"time"`
	Traceparent     string    `json:"traceparent,omitempty"`
	DataContentType string    `json:"datacontenttype"`
	Data            EventData `json:"data"`
	Actor           Principal `json:"-"`
	School          string    `json:"-"`
}
type AuditEntry struct {
	ID     string
	Actor  Principal
	Action string
	Target string
	School string
	Reason string
	Result string
	Time   time.Time
}
type EventData struct {
	Revision        int64    `json:"revision"`
	DesiredRevision int64    `json:"desired_revision"`
	AppliedRevision int64    `json:"applied_revision"`
	State           string   `json:"state"`
	Reason          string   `json:"reason,omitempty"`
	Warnings        []string `json:"warnings,omitempty"`
}
type OutboxReader interface {
	PendingOutbox(context.Context, int, []string) ([]Event, error)
	ConfirmOutbox(context.Context, string) error
}
type Repository interface {
	Transaction(context.Context, func(Transaction) error) error
	Claim(context.Context, string, time.Time, time.Duration) (Job, error)
	PendingEvents(context.Context, int) ([]Event, error)
	AcknowledgeEvent(context.Context, string) error
}

// Lock order is replay -> registry -> record -> job. Claim only locks a job, commits,
// then starts external work; a storage request never holds a module transaction.
type Transaction interface {
	UnsettledOwnerClosures(Principal, int) ([]Record, error)
	BoundInstances(Principal, []string) (map[string]bool, error)
	Lock(string) error
	Record(string) (Record, error)
	SaveRecord(Record) error
	List(Principal, int, string) ([]Record, error)
	Scan(int, string) ([]Record, error)
	ScanFiltered(n int, after, state, reason, adapter string) ([]Record, error)
	Counts(Principal) (total, owned int, err error)
	OwnerActivations(Principal, time.Time) (int, error)
	Job(string) (Job, error)
	JobsByIDs([]string) (map[string]Job, error)
	PendingOutboxBySubject([]string) (map[string]int, error)
	SaveJob(Job) error
	Replay(string) (Replay, error)
	SaveReplay(Replay) error
	PruneReplays(time.Time, int) error
	Event(Event) error
	Audit(AuditEntry) error
}

func hash(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// OwnerDomain is the stable storage ownership binding, including identity issuer.
func OwnerDomain(p Principal) string { return storage.ContributionOwnerDomain(p) }
