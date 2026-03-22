package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	sdkAuth "github.com/router-for-me/CLIProxyAPI/v6/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	_ "modernc.org/sqlite"
)

const defaultSQLiteAuthTable = "auth_store"

// SQLiteStore persists auth metadata in SQLite while mirroring auth JSON files
// to the configured auth directory for compatibility with the watcher.
type SQLiteStore struct {
	db        *sqlx.DB
	dbPath    string
	tableName string

	mu      sync.Mutex
	dirLock sync.RWMutex
	baseDir string
}

type sqliteAuthRecord struct {
	ID        string `db:"id"`
	Path      string `db:"path"`
	Content   string `db:"content"`
	CreatedAt int64  `db:"created_at"`
	UpdatedAt int64  `db:"updated_at"`
}

// NewSQLiteStore opens the SQLite database and prepares the auth table.
func NewSQLiteStore(ctx context.Context, dbPath string) (*SQLiteStore, error) {
	dbPath = strings.TrimSpace(dbPath)
	if dbPath == "" {
		return nil, fmt.Errorf("sqlite store: database path is required")
	}

	absPath, err := filepath.Abs(dbPath)
	if err != nil {
		return nil, fmt.Errorf("sqlite store: resolve database path: %w", err)
	}
	if err = os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
		return nil, fmt.Errorf("sqlite store: create database directory: %w", err)
	}

	dsn := "file:" + filepath.ToSlash(absPath) + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)"
	db, err := sqlx.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlite store: open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	store := &SQLiteStore{
		db:        db,
		dbPath:    absPath,
		tableName: defaultSQLiteAuthTable,
	}
	if err = store.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the underlying database connection.
func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// DBPath returns the absolute SQLite database path.
func (s *SQLiteStore) DBPath() string {
	if s == nil {
		return ""
	}
	return s.dbPath
}

// SetBaseDir updates the mirrored auth directory used for compatibility files.
func (s *SQLiteStore) SetBaseDir(dir string) {
	s.dirLock.Lock()
	s.baseDir = strings.TrimSpace(dir)
	s.dirLock.Unlock()
}

// AuthDir exposes the mirrored auth directory expected by the watcher.
func (s *SQLiteStore) AuthDir() string {
	return s.baseDirSnapshot()
}

// Bootstrap keeps the database and mirrored auth directory consistent on startup.
func (s *SQLiteStore) Bootstrap(ctx context.Context) error {
	return s.BootstrapFrom(ctx, "")
}

// BootstrapFrom optionally imports legacy auth JSON files from importDir when the
// database is empty, then rebuilds the compatibility mirror under the configured baseDir.
func (s *SQLiteStore) BootstrapFrom(ctx context.Context, importDir string) error {
	if err := s.ensureSchema(ctx); err != nil {
		return err
	}

	baseDir := s.baseDirSnapshot()
	if baseDir == "" {
		return nil
	}
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		return fmt.Errorf("sqlite store: create auth directory: %w", err)
	}

	count, err := s.recordCount(ctx)
	if err != nil {
		return err
	}
	if count == 0 {
		sourceDir := strings.TrimSpace(importDir)
		if sourceDir == "" {
			sourceDir = baseDir
		}
		if err = s.importAuthFiles(ctx, sourceDir); err != nil {
			return err
		}
	}
	return s.syncFilesFromDB(ctx)
}

// Save persists auth state to the mirrored JSON file and SQLite.
func (s *SQLiteStore) Save(ctx context.Context, auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("sqlite store: auth is nil")
	}

	path, err := s.resolveAuthPath(auth)
	if err != nil {
		return "", err
	}
	if path == "" {
		return "", fmt.Errorf("sqlite store: missing file path attribute for %s", auth.ID)
	}

	if auth.Disabled {
		if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
			return "", nil
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("sqlite store: create auth directory: %w", err)
	}

	type metadataSetter interface {
		SetMetadata(map[string]any)
	}

	switch {
	case auth.Storage != nil:
		if setter, ok := auth.Storage.(metadataSetter); ok {
			setter.SetMetadata(auth.Metadata)
		}
		if err = auth.Storage.SaveTokenToFile(path); err != nil {
			return "", err
		}
	case auth.Metadata != nil:
		auth.Metadata["disabled"] = auth.Disabled
		raw, errMarshal := json.Marshal(auth.Metadata)
		if errMarshal != nil {
			return "", fmt.Errorf("sqlite store: marshal metadata: %w", errMarshal)
		}
		if existing, errRead := os.ReadFile(path); errRead == nil && jsonEqual(existing, raw) {
			if err = s.upsertRecord(ctx, path, raw); err != nil {
				return "", err
			}
			s.attachPath(auth, path)
			return path, nil
		} else if errRead != nil && !errors.Is(errRead, os.ErrNotExist) {
			return "", fmt.Errorf("sqlite store: read existing auth file: %w", errRead)
		}
		if err = writeSQLiteFileAtomically(path, raw, 0o600); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("sqlite store: nothing to persist for %s", auth.ID)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("sqlite store: read mirrored auth file: %w", err)
	}
	if err = s.upsertRecord(ctx, path, payload); err != nil {
		return "", err
	}

	s.attachPath(auth, path)
	return path, nil
}

// List returns all auth records stored in SQLite.
func (s *SQLiteStore) List(ctx context.Context) ([]*cliproxyauth.Auth, error) {
	rows := make([]sqliteAuthRecord, 0, 16)
	query := fmt.Sprintf("SELECT id, path, content, created_at, updated_at FROM %s ORDER BY id", s.tableName)
	if err := s.db.SelectContext(ctx, &rows, query); err != nil {
		return nil, fmt.Errorf("sqlite store: list auth: %w", err)
	}

	auths := make([]*cliproxyauth.Auth, 0, len(rows))
	for _, row := range rows {
		auth, err := s.recordToAuth(ctx, row)
		if err != nil {
			continue
		}
		auths = append(auths, auth)
	}
	return auths, nil
}

// Delete removes an auth record from SQLite and the mirrored file.
func (s *SQLiteStore) Delete(ctx context.Context, id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("sqlite store: id is empty")
	}

	path, err := s.resolveDeletePath(id)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if err = os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sqlite store: delete auth file: %w", err)
	}

	recordID, err := s.relativeAuthID(path)
	if err != nil {
		return err
	}
	query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", s.tableName)
	if _, err = s.db.ExecContext(ctx, query, recordID); err != nil {
		return fmt.Errorf("sqlite store: delete auth record: %w", err)
	}
	return nil
}

// PersistConfig is a no-op because this store only manages auth persistence.
func (s *SQLiteStore) PersistConfig(context.Context) error {
	return nil
}

// PersistAuthFiles syncs mirrored auth file changes back into SQLite.
func (s *SQLiteStore) PersistAuthFiles(ctx context.Context, _ string, paths ...string) error {
	if len(paths) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range paths {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}

		absPath := trimmed
		if !filepath.IsAbs(absPath) {
			baseDir := s.baseDirSnapshot()
			if baseDir == "" {
				return fmt.Errorf("sqlite store: auth directory not configured")
			}
			absPath = filepath.Join(baseDir, filepath.FromSlash(trimmed))
		}

		recordID, err := s.relativeAuthID(absPath)
		if err != nil {
			return err
		}

		data, err := os.ReadFile(absPath)
		switch {
		case errors.Is(err, os.ErrNotExist):
			query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", s.tableName)
			if _, execErr := s.db.ExecContext(ctx, query, recordID); execErr != nil {
				return fmt.Errorf("sqlite store: delete auth record: %w", execErr)
			}
		case err != nil:
			return fmt.Errorf("sqlite store: read auth file: %w", err)
		case len(data) == 0:
			query := fmt.Sprintf("DELETE FROM %s WHERE id = ?", s.tableName)
			if _, execErr := s.db.ExecContext(ctx, query, recordID); execErr != nil {
				return fmt.Errorf("sqlite store: delete empty auth record: %w", execErr)
			}
		default:
			if err = s.upsertRecord(ctx, absPath, data); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *SQLiteStore) ensureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("sqlite store: not initialized")
	}

	query := fmt.Sprintf(`
		CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			path TEXT NOT NULL,
			content TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			updated_at INTEGER NOT NULL
		)
	`, s.tableName)
	if _, err := s.db.ExecContext(ctx, query); err != nil {
		return fmt.Errorf("sqlite store: create auth table: %w", err)
	}
	return nil
}

func (s *SQLiteStore) recordCount(ctx context.Context) (int, error) {
	query := fmt.Sprintf("SELECT COUNT(1) FROM %s", s.tableName)
	var count int
	if err := s.db.GetContext(ctx, &count, query); err != nil {
		return 0, fmt.Errorf("sqlite store: count auth records: %w", err)
	}
	return count, nil
}

func (s *SQLiteStore) importAuthFiles(ctx context.Context, dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	baseDir := s.baseDirSnapshot()
	if baseDir == "" {
		return nil
	}
	if _, err := os.Stat(dir); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("sqlite store: stat import directory: %w", err)
	}

	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".json") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if len(data) == 0 {
			return nil
		}
		relPath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("sqlite store: resolve import path: %w", err)
		}
		targetPath := filepath.Join(baseDir, relPath)
		return s.upsertRecord(ctx, targetPath, data)
	})
}

func (s *SQLiteStore) syncFilesFromDB(ctx context.Context) error {
	baseDir := s.baseDirSnapshot()
	if baseDir == "" {
		return nil
	}

	rows := make([]sqliteAuthRecord, 0, 16)
	query := fmt.Sprintf("SELECT id, path, content, created_at, updated_at FROM %s ORDER BY id", s.tableName)
	if err := s.db.SelectContext(ctx, &rows, query); err != nil {
		return fmt.Errorf("sqlite store: read auth records: %w", err)
	}

	for _, row := range rows {
		path, err := s.absoluteAuthPath(row.ID)
		if err != nil {
			return err
		}
		if err = writeSQLiteFileAtomically(path, []byte(row.Content), 0o600); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStore) upsertRecord(ctx context.Context, path string, payload []byte) error {
	if len(payload) == 0 {
		return nil
	}

	recordID, err := s.relativeAuthID(path)
	if err != nil {
		return err
	}
	now := time.Now().UTC().UnixMilli()
	query := fmt.Sprintf(`
		INSERT INTO %s (id, path, content, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			path = excluded.path,
			content = excluded.content,
			updated_at = excluded.updated_at
	`, s.tableName)
	if _, err = s.db.ExecContext(ctx, query, recordID, path, string(payload), now, now); err != nil {
		return fmt.Errorf("sqlite store: upsert auth record: %w", err)
	}
	return nil
}

func (s *SQLiteStore) recordToAuth(ctx context.Context, row sqliteAuthRecord) (*cliproxyauth.Auth, error) {
	metadata := make(map[string]any)
	if err := json.Unmarshal([]byte(row.Content), &metadata); err != nil {
		return nil, fmt.Errorf("sqlite store: unmarshal auth json: %w", err)
	}

	if err := s.maybeHydrateProjectID(ctx, row, metadata); err != nil {
		return nil, err
	}

	provider, _ := metadata["type"].(string)
	if provider == "" {
		provider = "unknown"
	}
	disabled, _ := metadata["disabled"].(bool)
	status := cliproxyauth.StatusActive
	if disabled {
		status = cliproxyauth.StatusDisabled
	}

	path := strings.TrimSpace(row.Path)
	if path == "" {
		var err error
		path, err = s.absoluteAuthPath(row.ID)
		if err != nil {
			return nil, err
		}
	}

	attrs := map[string]string{"path": path}
	if email, ok := metadata["email"].(string); ok {
		email = strings.TrimSpace(email)
		if email != "" {
			attrs["email"] = email
		}
	}

	return &cliproxyauth.Auth{
		ID:               normalizeSQLiteAuthID(row.ID),
		Provider:         provider,
		FileName:         normalizeSQLiteAuthID(row.ID),
		Label:            sqliteLabelFor(metadata),
		Status:           status,
		Disabled:         disabled,
		Attributes:       attrs,
		Metadata:         metadata,
		CreatedAt:        time.UnixMilli(row.CreatedAt).UTC(),
		UpdatedAt:        time.UnixMilli(row.UpdatedAt).UTC(),
		LastRefreshedAt:  time.Time{},
		NextRefreshAfter: time.Time{},
	}, nil
}

func (s *SQLiteStore) maybeHydrateProjectID(ctx context.Context, row sqliteAuthRecord, metadata map[string]any) error {
	provider, _ := metadata["type"].(string)
	if provider != "antigravity" && provider != "gemini" {
		return nil
	}

	projectID, _ := metadata["project_id"].(string)
	if strings.TrimSpace(projectID) != "" {
		return nil
	}

	accessToken := extractSQLiteAccessToken(metadata)
	if provider == "gemini" {
		if tokenMap, ok := metadata["token"].(map[string]any); ok {
			refreshed, err := refreshSQLiteGeminiAccessToken(tokenMap, http.DefaultClient)
			if err == nil && strings.TrimSpace(refreshed) != "" {
				accessToken = refreshed
			}
		}
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil
	}

	fetchedProjectID, err := sdkAuth.FetchAntigravityProjectID(ctx, accessToken, http.DefaultClient)
	if err != nil || strings.TrimSpace(fetchedProjectID) == "" {
		return nil
	}

	metadata["project_id"] = strings.TrimSpace(fetchedProjectID)
	raw, err := json.Marshal(metadata)
	if err != nil {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	path := strings.TrimSpace(row.Path)
	if path == "" {
		path, err = s.absoluteAuthPath(row.ID)
		if err != nil {
			return nil
		}
	}
	if err = writeSQLiteFileAtomically(path, raw, 0o600); err != nil {
		return nil
	}
	return s.upsertRecord(ctx, path, raw)
}

func (s *SQLiteStore) attachPath(auth *cliproxyauth.Auth, path string) {
	if auth.Attributes == nil {
		auth.Attributes = make(map[string]string)
	}
	auth.Attributes["path"] = path
	if strings.TrimSpace(auth.FileName) == "" {
		auth.FileName = auth.ID
	}
}

func (s *SQLiteStore) resolveAuthPath(auth *cliproxyauth.Auth) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("sqlite store: auth is nil")
	}
	if auth.Attributes != nil {
		if p := strings.TrimSpace(auth.Attributes["path"]); p != "" {
			return p, nil
		}
	}
	if fileName := strings.TrimSpace(auth.FileName); fileName != "" {
		if filepath.IsAbs(fileName) {
			return fileName, nil
		}
		dir := s.baseDirSnapshot()
		if dir == "" {
			return "", fmt.Errorf("sqlite store: auth directory not configured")
		}
		return filepath.Join(dir, filepath.FromSlash(fileName)), nil
	}
	if auth.ID == "" {
		return "", fmt.Errorf("sqlite store: missing id")
	}
	if filepath.IsAbs(auth.ID) {
		return auth.ID, nil
	}
	dir := s.baseDirSnapshot()
	if dir == "" {
		return "", fmt.Errorf("sqlite store: auth directory not configured")
	}
	return filepath.Join(dir, filepath.FromSlash(auth.ID)), nil
}

func (s *SQLiteStore) resolveDeletePath(id string) (string, error) {
	if strings.ContainsRune(id, os.PathSeparator) || filepath.IsAbs(id) {
		return id, nil
	}
	dir := s.baseDirSnapshot()
	if dir == "" {
		return "", fmt.Errorf("sqlite store: auth directory not configured")
	}
	return filepath.Join(dir, filepath.FromSlash(id)), nil
}

func (s *SQLiteStore) relativeAuthID(path string) (string, error) {
	baseDir := s.baseDirSnapshot()
	if baseDir == "" {
		return "", fmt.Errorf("sqlite store: auth directory not configured")
	}

	if !filepath.IsAbs(path) {
		path = filepath.Join(baseDir, path)
	}
	clean := filepath.Clean(path)
	rel, err := filepath.Rel(baseDir, clean)
	if err != nil {
		return "", fmt.Errorf("sqlite store: compute relative path: %w", err)
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("sqlite store: path %s outside managed directory", path)
	}
	return normalizeSQLiteAuthID(rel), nil
}

func (s *SQLiteStore) absoluteAuthPath(id string) (string, error) {
	baseDir := s.baseDirSnapshot()
	if baseDir == "" {
		return "", fmt.Errorf("sqlite store: auth directory not configured")
	}

	clean := filepath.Clean(filepath.FromSlash(id))
	if strings.HasPrefix(clean, "..") {
		return "", fmt.Errorf("sqlite store: invalid auth identifier %s", id)
	}
	path := filepath.Join(baseDir, clean)
	rel, err := filepath.Rel(baseDir, path)
	if err != nil {
		return "", fmt.Errorf("sqlite store: resolve auth path: %w", err)
	}
	if strings.HasPrefix(rel, "..") {
		return "", fmt.Errorf("sqlite store: resolved path escapes auth directory")
	}
	return path, nil
}

func (s *SQLiteStore) baseDirSnapshot() string {
	s.dirLock.RLock()
	defer s.dirLock.RUnlock()
	return s.baseDir
}

func sqliteLabelFor(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	if v, ok := metadata["label"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := metadata["email"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v, ok := metadata["project_id"].(string); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return ""
}

func normalizeSQLiteAuthID(id string) string {
	id = filepath.ToSlash(filepath.Clean(id))
	if runtime.GOOS == "windows" {
		id = strings.ToLower(id)
	}
	return id
}

func extractSQLiteAccessToken(metadata map[string]any) string {
	if at, ok := metadata["access_token"].(string); ok {
		if v := strings.TrimSpace(at); v != "" {
			return v
		}
	}
	if tokenMap, ok := metadata["token"].(map[string]any); ok {
		if at, ok := tokenMap["access_token"].(string); ok {
			if v := strings.TrimSpace(at); v != "" {
				return v
			}
		}
	}
	return ""
}

func refreshSQLiteGeminiAccessToken(tokenMap map[string]any, httpClient *http.Client) (string, error) {
	refreshToken, _ := tokenMap["refresh_token"].(string)
	clientID, _ := tokenMap["client_id"].(string)
	clientSecret, _ := tokenMap["client_secret"].(string)
	tokenURI, _ := tokenMap["token_uri"].(string)

	if refreshToken == "" || clientID == "" || clientSecret == "" {
		return "", fmt.Errorf("missing refresh credentials")
	}
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token"
	}

	data := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}

	resp, err := httpClient.PostForm(tokenURI, data)
	if err != nil {
		return "", fmt.Errorf("refresh request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("refresh failed: status %d", resp.StatusCode)
	}

	var result map[string]any
	if err = json.Unmarshal(body, &result); err != nil {
		return "", fmt.Errorf("decode refresh response: %w", err)
	}

	newAccessToken, _ := result["access_token"].(string)
	if newAccessToken == "" {
		return "", fmt.Errorf("no access_token in refresh response")
	}

	tokenMap["access_token"] = newAccessToken
	return newAccessToken, nil
}

func writeSQLiteFileAtomically(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("sqlite store: create auth directory: %w", err)
	}
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, data, perm); err != nil {
		return fmt.Errorf("sqlite store: write temp auth file: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sqlite store: rename auth file: %w", err)
	}
	return nil
}
