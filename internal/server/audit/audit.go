// Package audit writes and verifies the tamper-evident audit log.
//
// Every event stores hash = SHA-256(prev_hash || encode(event)), where prev_hash is the
// hash of the previous event. Changing, inserting or deleting an event in the middle of
// the log breaks the chain, which Verify detects. Deleting events at the end cannot be
// detected from the chain alone; exporting the log off-host (Phase 3) covers that.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/monirujjaman-dev/server-manager/internal/server/store/db"
)

// ActorType identifies who performed an action.
type ActorType string

// Actor types, matching the database CHECK constraint.
const (
	ActorUser   ActorType = "user"
	ActorAgent  ActorType = "agent"
	ActorSystem ActorType = "system"
)

// Result is the outcome recorded for an action.
type Result string

// Results, matching the database CHECK constraint.
const (
	Requested Result = "requested"
	Succeeded Result = "succeeded"
	Failed    Result = "failed"
	Denied    Result = "denied"
)

// Event is one audit entry. Params holds strings only, so the hashed encoding is
// identical before and after a round trip through PostgreSQL jsonb. Never put secrets
// in Params.
type Event struct {
	Time      time.Time
	ActorType ActorType
	ActorID   string
	SourceIP  *netip.Addr
	ServerID  *uuid.UUID
	Action    string
	Params    map[string]string
	Result    Result
}

// Append writes ev using q, which should belong to the same transaction as the change
// the event describes, so that both commit or neither does. It takes a transaction-level
// advisory lock to serialize appends; q must therefore be bound to a transaction.
func Append(ctx context.Context, q *db.Queries, ev Event) (int64, error) {
	if ev.ActorID == "" || ev.Action == "" || ev.ActorType == "" || ev.Result == "" {
		return 0, errors.New("audit: actor, action and result are required")
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	// PostgreSQL stores microseconds; hash exactly what will be read back.
	ev.Time = ev.Time.UTC().Truncate(time.Microsecond)
	if ev.Params == nil {
		ev.Params = map[string]string{}
	}
	params, err := json.Marshal(ev.Params) // map keys are sorted: canonical
	if err != nil {
		return 0, err
	}

	if err := q.LockAuditChain(ctx); err != nil {
		return 0, fmt.Errorf("audit: lock: %w", err)
	}
	prev, err := q.LatestAuditHash(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = nil
	} else if err != nil {
		return 0, fmt.Errorf("audit: previous hash: %w", err)
	}
	hash := chainHash(prev, ev, params)
	id, err := q.InsertAuditEvent(ctx, db.InsertAuditEventParams{
		Ts: ev.Time, ActorType: string(ev.ActorType), ActorID: ev.ActorID, SourceIP: ev.SourceIP,
		ServerID: ev.ServerID, Action: ev.Action, Params: params, Result: string(ev.Result),
		PrevHash: prev, Hash: hash,
	})
	if err != nil {
		return 0, fmt.Errorf("audit: insert: %w", err)
	}
	return id, nil
}

// ErrChainBroken reports the first event whose hash or link does not match.
type ErrChainBroken struct {
	EventID int64
	Reason  string
}

func (e *ErrChainBroken) Error() string {
	return fmt.Sprintf("audit chain broken at event %d: %s", e.EventID, e.Reason)
}

// Verify walks the whole log and recomputes every hash. It returns the number of events
// checked and an *ErrChainBroken for the first inconsistency.
func Verify(ctx context.Context, q *db.Queries) (int, error) {
	const page = 1000
	var prev []byte
	var after int64
	checked := 0
	for {
		rows, err := q.ListAuditEvents(ctx, db.ListAuditEventsParams{AfterID: after, MaxRows: page})
		if err != nil {
			return checked, err
		}
		for _, r := range rows {
			if !bytes.Equal(r.PrevHash, prev) {
				return checked, &ErrChainBroken{EventID: r.ID, Reason: "previous-hash link does not match the preceding event"}
			}
			params, err := canonicalParams(r.Params)
			if err != nil {
				return checked, &ErrChainBroken{EventID: r.ID, Reason: "params are not a string map"}
			}
			ev := Event{
				Time: r.Ts.UTC(), ActorType: ActorType(r.ActorType), ActorID: r.ActorID, SourceIP: r.SourceIP,
				ServerID: r.ServerID, Action: r.Action, Result: Result(r.Result),
			}
			if !bytes.Equal(chainHash(prev, ev, params), r.Hash) {
				return checked, &ErrChainBroken{EventID: r.ID, Reason: "content does not match its hash"}
			}
			prev = r.Hash
			after = r.ID
			checked++
		}
		if len(rows) < page {
			return checked, nil
		}
	}
}

func canonicalParams(raw []byte) ([]byte, error) {
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return json.Marshal(m)
}

// chainHash computes SHA-256(prev || encode(ev)). The encoding length-prefixes every
// field so that no two different events encode to the same bytes.
func chainHash(prev []byte, ev Event, params []byte) []byte {
	h := sha256.New()
	h.Write(prev)
	field := func(s string) {
		var n [binary.MaxVarintLen64]byte
		h.Write(n[:binary.PutUvarint(n[:], uint64(len(s)))])
		h.Write([]byte(s))
	}
	field("sm-audit-v1")
	field(ev.Time.UTC().Format(time.RFC3339Nano))
	field(string(ev.ActorType))
	field(ev.ActorID)
	if ev.SourceIP != nil {
		field(ev.SourceIP.String())
	} else {
		field("")
	}
	if ev.ServerID != nil {
		field(ev.ServerID.String())
	} else {
		field("")
	}
	field(ev.Action)
	field(string(params))
	field(string(ev.Result))
	return h.Sum(nil)
}
