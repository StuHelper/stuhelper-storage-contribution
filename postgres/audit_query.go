package postgres

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	a "github.com/StuHelper/stuhelper-storage-contribution/auditquery"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var _ a.Reader = (*Repository)(nil)

func encodeAuditSnapshot(epoch int64, visibility string) (string, error) {
	prefix := strconv.FormatInt(epoch, 10) + "|"
	if len(prefix)+len(visibility) <= 256 {
		return prefix + visibility, nil
	}
	parts := strings.Split(visibility, ":")
	if len(parts) != 3 {
		return "", a.ErrUnavailable
	}
	xmin, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return "", a.ErrUnavailable
	}
	xmax, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil || xmax < xmin {
		return "", a.ErrUnavailable
	}
	var xips []uint64
	if parts[2] != "" {
		items := strings.Split(parts[2], ",")
		xips = make([]uint64, 0, len(items))
		for _, item := range items {
			x, err := strconv.ParseUint(item, 10, 64)
			if err != nil || x < xmin || x >= xmax {
				return "", a.ErrUnavailable
			}
			xips = append(xips, x)
		}
		slices.Sort(xips)
		for i := 1; i < len(xips); i++ {
			if xips[i] <= xips[i-1] {
				return "", a.ErrUnavailable
			}
		}
	}
	buf := make([]byte, 0, 16+len(xips)*2)
	buf = binary.AppendUvarint(buf, xmin)
	buf = binary.AppendUvarint(buf, xmax-xmin)
	buf = binary.AppendUvarint(buf, uint64(len(xips)))
	prev := xmin
	for i, x := range xips {
		if i == 0 {
			buf = binary.AppendUvarint(buf, x-prev)
		} else {
			buf = binary.AppendUvarint(buf, x-prev-1)
		}
		prev = x
	}
	compact := prefix + "~" + base64.RawURLEncoding.EncodeToString(buf)
	if len(compact) > 256 {
		return "", a.ErrUnavailable
	}
	return compact, nil
}

func decodeAuditVisibility(token string) (string, error) {
	if !strings.HasPrefix(token, "~") {
		for _, r := range token {
			if (r < '0' || r > '9') && r != ':' && r != ',' {
				return "", a.ErrUnavailable
			}
		}
		return token, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token[1:])
	if err != nil {
		return "", a.ErrUnavailable
	}
	readVarint := func() (uint64, bool) {
		v, n := binary.Uvarint(raw)
		if n <= 0 {
			return 0, false
		}
		raw = raw[n:]
		return v, true
	}
	xmin, ok := readVarint()
	if !ok {
		return "", a.ErrUnavailable
	}
	span, ok := readVarint()
	if !ok || xmin+span < xmin {
		return "", a.ErrUnavailable
	}
	xmax := xmin + span
	count, ok := readVarint()
	if !ok || count > 512 {
		return "", a.ErrUnavailable
	}
	var b strings.Builder
	b.WriteString(strconv.FormatUint(xmin, 10))
	b.WriteByte(':')
	b.WriteString(strconv.FormatUint(xmax, 10))
	b.WriteByte(':')
	prev := xmin
	for i := uint64(0); i < count; i++ {
		delta, ok := readVarint()
		if !ok {
			return "", a.ErrUnavailable
		}
		var x uint64
		if i == 0 {
			x = prev + delta
			if x < prev {
				return "", a.ErrUnavailable
			}
		} else {
			x = prev + delta + 1
			if x <= prev {
				return "", a.ErrUnavailable
			}
		}
		if x >= xmax {
			return "", a.ErrUnavailable
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.FormatUint(x, 10))
		prev = x
	}
	if len(raw) != 0 {
		return "", a.ErrUnavailable
	}
	return b.String(), nil
}

func auditText(v string, n int) bool {
	return len(v) <= n && !strings.ContainsFunc(v, unicode.IsControl)
}

// ReadAudit reads only explicitly projected sanitized fields inside a repeatable-read
// transaction. Visibility excludes late commits; epoch invalidates modified or pruned rows.
func (r *Repository) ReadAudit(ctx context.Context, q a.Request) (out a.Batch, err error) {
	out.Records = []a.Record{}
	if q.Limit < 1 || q.Limit > 101 || len(q.Scopes) > 1000 || q.Until.IsZero() || (!q.From.IsZero() && !q.From.Before(q.Until)) || len(q.Snapshot) > 256 {
		return out, a.ErrInvalid
	}
	for _, v := range []string{q.Actor, q.Target} {
		if !auditText(v, 2048) {
			return out, a.ErrInvalid
		}
	}
	if !auditText(q.Action, 128) {
		return out, a.ErrInvalid
	}
	for _, s := range q.Scopes {
		for _, v := range []string{s.School, s.Group, s.Module} {
			if v == "" || !auditText(v, 256) {
				return out, a.ErrInvalid
			}
		}
	}
	if q.Before != nil && (q.Before.Time.IsZero() || q.Before.ID == "" || !auditText(q.Before.ID, 256) || q.Before.Source == "" || !auditText(q.Before.Source, 64)) {
		return out, a.ErrInvalid
	}
	defer func() {
		if err != nil && err != a.ErrInvalid {
			if ctx.Err() != nil {
				err = ctx.Err()
			} else {
				err = a.ErrUnavailable
			}
		}
	}()
	tx, err := r.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var epoch int64
	if err = tx.QueryRowContext(ctx, `SELECT revision FROM contribution.audit_retention WHERE singleton`).Scan(&epoch); err != nil {
		return out, err
	}
	var visibility string
	if q.Snapshot == "" {
		if err = tx.QueryRowContext(ctx, `SELECT pg_current_snapshot()::text`).Scan(&visibility); err != nil {
			return out, err
		}
	} else {
		previous, token, ok := strings.Cut(q.Snapshot, "|")
		if !ok || previous != strconv.FormatInt(epoch, 10) {
			return out, a.ErrUnavailable
		}
		visibility, err = decodeAuditVisibility(token)
		if err != nil {
			return out, err
		}
	}
	out.Snapshot, err = encodeAuditSnapshot(epoch, visibility)
	if err != nil {
		return out, err
	}
	scopes, _ := json.Marshal(append([]a.Scope{}, q.Scopes...))
	var from, before any
	if !q.From.IsZero() {
		from = q.From
	}
	source, id := "", ""
	if q.Before != nil {
		before = q.Before.Time
		source = q.Before.Source
		id = q.Before.ID
	}
	rows, err := tx.QueryContext(ctx, `SELECT id::text,audit_actor,audit_target,audit_action,audit_school,audit_group,reason,result,audit_time
 FROM contribution.audit a WHERE pg_visible_in_snapshot(recorded_xid,$1::pg_snapshot)
 AND EXISTS(SELECT 1 FROM jsonb_to_recordset($2::jsonb) s(school text,"group" text,module text) WHERE (s.school='*' OR s.school=a.audit_school) AND (s."group"='*' OR s."group"=a.audit_group) AND s.module IN ('*','storage-contribution'))
 AND ($3='' OR audit_actor=$3) AND ($4='' OR audit_target=$4) AND ($5='' OR audit_action=$5)
 AND ($6::timestamptz IS NULL OR audit_time >= $6) AND audit_time < $7
 AND ($8::timestamptz IS NULL OR (audit_time,'storage-contribution' COLLATE "C",id::text COLLATE "C") < ($8,$9::text COLLATE "C",$10::text COLLATE "C"))
 ORDER BY audit_time DESC,id::text COLLATE "C" DESC LIMIT $11`, visibility, scopes, q.Actor, q.Target, q.Action, from, q.Until, before, source, id, q.Limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		v := a.Record{Source: "storage-contribution", Scope: a.Scope{Module: "storage-contribution"}}
		if err = rows.Scan(&v.ID, &v.Actor, &v.Target, &v.Action, &v.Scope.School, &v.Scope.Group, &v.Reason, &v.Result, &v.CreatedAt); err != nil {
			return out, err
		}
		if !auditText(v.Reason, 512) {
			v.Reason = ""
		}
		out.Records = append(out.Records, v)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	err = tx.Commit()
	return out, err
}
