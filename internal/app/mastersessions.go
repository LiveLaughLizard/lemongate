package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// masterRow is the settings row holding a fingerprint of the master key, kept out of
// the readable settings document.
const masterRow = "master_key_fingerprint"

// revokeStaleMasterSessions signs out every console session opened with the master key
// when the key has changed since the last start, so rotating a leaked key also ends
// the sessions created with it.
func revokeStaleMasterSessions(ctx context.Context, pool *pgxpool.Pool, masterKey string) error {
	sum := sha256.Sum256([]byte("lemongate/master-fingerprint/v1:" + masterKey))
	fp, _ := json.Marshal(hex.EncodeToString(sum[:]))
	var stored []byte
	_ = pool.QueryRow(ctx, `SELECT value FROM settings WHERE key = $1`, masterRow).Scan(&stored)
	var a, b any
	if json.Unmarshal(stored, &a) == nil && json.Unmarshal(fp, &b) == nil && a == b {
		return nil
	}
	tag, err := pool.Exec(ctx, `DELETE FROM sessions WHERE is_master`)
	if err != nil {
		return err
	}
	if n := tag.RowsAffected(); n > 0 {
		slog.Info("master key changed: signed out master-key sessions", "count", n)
	}
	_, err = pool.Exec(ctx, `INSERT INTO settings(key, value, updated_at) VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`, masterRow, fp)
	return err
}
