package main

import (
	"context"
	"log"
	"time"

	"synsec/internal/store"
)

// Housekeeping intervals.
const (
	// janitorEvery is how often the sweep runs. Hourly is far more often than
	// needed for a household and still cheap: two DELETE statements.
	janitorEvery = time.Hour

	// janitorFirstDelay lets the server finish starting before the first
	// sweep, so a slow disk does not delay the moment devices can be served.
	janitorFirstDelay = time.Minute
)

// startJanitor removes what nobody can use any more.
//
// Sessions and audit entries both grow without limit otherwise. On a home
// network that is merely untidy; on a server anyone can reach, every failed
// sign-in writes a row, and a disk that fills is a server that stops - a
// denial of service that needs no flaw, only patience.
func startJanitor(ctx context.Context, db *store.DB, retain time.Duration) {
	go func() {
		timer := time.NewTimer(janitorFirstDelay)
		defer timer.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}

			sweep(ctx, db, retain)
			timer.Reset(janitorEvery)
		}
	}()
}

// sweep does one pass. Failures are logged and the loop continues: tidying is
// not worth stopping a server over.
func sweep(ctx context.Context, db *store.DB, retain time.Duration) {
	if n, err := db.PurgeExpiredSessions(ctx, time.Now()); err != nil {
		log.Printf("ménage : sessions expirées : %v", err)
	} else if n > 0 {
		log.Printf("ménage : %d session(s) expirée(s) supprimée(s)", n)
	}

	// A retention of zero keeps the log for ever, which is the right default
	// for a machine holding a household's history: nobody wants to discover
	// that the trace of an intrusion aged out.
	if retain <= 0 {
		return
	}
	cutoff := time.Now().Add(-retain)
	if n, err := db.PurgeAuditBefore(ctx, cutoff); err != nil {
		log.Printf("ménage : journal d'audit : %v", err)
	} else if n > 0 {
		log.Printf("ménage : %d ligne(s) de journal antérieure(s) au %s supprimée(s)",
			n, cutoff.Format("02/01/2006"))
	}
}
