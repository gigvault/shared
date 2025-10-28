package keystore

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// KeyStorage handles persistence of encrypted keys
type KeyStorage struct {
	db *sql.DB
}

// NewKeyStorage creates a new key storage
func NewKeyStorage(db *sql.DB) *KeyStorage {
	return &KeyStorage{db: db}
}

// Store stores an encrypted key in the database
func (s *KeyStorage) Store(ctx context.Context, key *EncryptedKey) error {
	query := `
		INSERT INTO encrypted_keys (
			key_id, encrypted_dek, encrypted_key, nonce,
			algorithm, created_at, rotated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (key_id) DO UPDATE SET
			encrypted_dek = EXCLUDED.encrypted_dek,
			encrypted_key = EXCLUDED.encrypted_key,
			nonce = EXCLUDED.nonce,
			rotated_at = EXCLUDED.rotated_at
	`

	_, err := s.db.ExecContext(ctx, query,
		key.KeyID,
		key.EncryptedDEK,
		key.EncryptedKey,
		key.Nonce,
		key.Algorithm,
		time.Unix(key.CreatedAt, 0),
		time.Unix(key.RotatedAt, 0),
	)

	if err != nil {
		return fmt.Errorf("failed to store encrypted key: %w", err)
	}

	return nil
}

// Get retrieves an encrypted key from the database
func (s *KeyStorage) Get(ctx context.Context, keyID string) (*EncryptedKey, error) {
	query := `
		SELECT key_id, encrypted_dek, encrypted_key, nonce,
		       algorithm, created_at, rotated_at
		FROM encrypted_keys
		WHERE key_id = $1
	`

	var key EncryptedKey
	var createdAt, rotatedAt time.Time

	err := s.db.QueryRowContext(ctx, query, keyID).Scan(
		&key.KeyID,
		&key.EncryptedDEK,
		&key.EncryptedKey,
		&key.Nonce,
		&key.Algorithm,
		&createdAt,
		&rotatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get encrypted key: %w", err)
	}

	key.CreatedAt = createdAt.Unix()
	key.RotatedAt = rotatedAt.Unix()

	return &key, nil
}

// List lists all key IDs
func (s *KeyStorage) List(ctx context.Context) ([]string, error) {
	query := `SELECT key_id FROM encrypted_keys ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer rows.Close()

	var keyIDs []string
	for rows.Next() {
		var keyID string
		if err := rows.Scan(&keyID); err != nil {
			return nil, fmt.Errorf("failed to scan key ID: %w", err)
		}
		keyIDs = append(keyIDs, keyID)
	}

	return keyIDs, nil
}

// Delete deletes an encrypted key (DANGEROUS - audit this!)
func (s *KeyStorage) Delete(ctx context.Context, keyID string) error {
	query := `DELETE FROM encrypted_keys WHERE key_id = $1`

	result, err := s.db.ExecContext(ctx, query, keyID)
	if err != nil {
		return fmt.Errorf("failed to delete encrypted key: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rows == 0 {
		return fmt.Errorf("key not found: %s", keyID)
	}

	return nil
}

// Export exports an encrypted key for backup (should be encrypted at rest!)
func (s *KeyStorage) Export(ctx context.Context, keyID string) ([]byte, error) {
	key, err := s.Get(ctx, keyID)
	if err != nil {
		return nil, err
	}

	// Export as JSON
	data, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal key: %w", err)
	}

	return data, nil
}

// Import imports an encrypted key from backup
func (s *KeyStorage) Import(ctx context.Context, data []byte) error {
	var key EncryptedKey
	if err := json.Unmarshal(data, &key); err != nil {
		return fmt.Errorf("failed to unmarshal key: %w", err)
	}

	return s.Store(ctx, &key)
}
