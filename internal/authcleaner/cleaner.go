package authcleaner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

var (
	pattern401   = regexp.MustCompile(`(?i)(^|\D)401(\D|$)|unauthorized|unauthenticated|token\s+expired|login\s+required|authentication\s+failed`)
	patternQuota = regexp.MustCompile(`(?i)(^|\D)(402|403|429)(\D|$)|quota|insufficient\s*quota|resource\s*exhausted|rate\s*limit|too\s+many\s+requests|payment\s+required|billing|credit|额度|用完|超限|上限|usage_limit_reached`)
)

type Options struct {
	DryRun   bool
	Once     bool
	Interval time.Duration
}

type TokenStore interface {
	Delete(context.Context, string) error
}

type Summary struct {
	Checked       int `json:"checked"`
	Available     int `json:"available"`
	QuotaExceeded int `json:"quota_exceeded"`
	Disabled      int `json:"disabled"`
	Unavailable   int `json:"unavailable"`
	Delete401     int `json:"delete_401"`
	Deleted       int `json:"deleted"`
	BackupFailed  int `json:"backup_failed"`
	DeleteFailed  int `json:"delete_failed"`
}

type Result struct {
	ID                  string `json:"id,omitempty"`
	Name                string `json:"name"`
	Provider            string `json:"provider,omitempty"`
	AuthIndex           string `json:"auth_index,omitempty"`
	Status              string `json:"status,omitempty"`
	StatusMessage       string `json:"status_message,omitempty"`
	FinalClassification string `json:"final_classification"`
	Reason              string `json:"reason,omitempty"`
	DeleteResult        string `json:"delete_result,omitempty"`
	DeleteError         string `json:"delete_error,omitempty"`
	BackupPath          string `json:"backup_path,omitempty"`
}

type Report struct {
	RunID       string   `json:"run_id"`
	DryRun      bool     `json:"dry_run"`
	Results     []Result `json:"results"`
	Summary     Summary  `json:"summary"`
	GeneratedAt string   `json:"generated_at"`
}

type jsonError struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

type classifiedError struct {
	Type    string
	Message string
}

type Cleaner struct {
	manager  *coreauth.Manager
	store    TokenStore
	deleteFn func(context.Context, string) error
	updateFn func(context.Context, *coreauth.Auth) error
	logger   *log.Entry
}

func New(manager *coreauth.Manager, store TokenStore) *Cleaner {
	cleaner := &Cleaner{
		manager: manager,
		store:   store,
		logger:  log.WithField("component", "auth-cleaner"),
	}
	cleaner.deleteFn = cleaner.defaultDeleteAuth
	cleaner.updateFn = cleaner.defaultUpdateAuth
	return cleaner
}

func (c *Cleaner) RunLoop(ctx context.Context, opts Options) error {
	if c == nil || c.manager == nil {
		return fmt.Errorf("auth cleaner: core manager is unavailable")
	}
	if opts.Interval <= 0 {
		opts.Interval = time.Minute
	}

	printBanner(opts)
	if opts.Once {
		_, err := c.RunOnce(ctx, opts.DryRun)
		return err
	}

	loopCount := 0
	for {
		select {
		case <-ctx.Done():
			fmt.Printf("\nAuth cleaner stopped after %d checks\n", loopCount)
			return nil
		default:
		}

		loopCount++
		fmt.Printf("\n%s\n", strings.Repeat("-", 60))
		fmt.Printf("Check #%d at %s\n", loopCount, time.Now().Format(time.RFC3339))
		fmt.Printf("%s\n", strings.Repeat("-", 60))
		if _, err := c.RunOnce(ctx, opts.DryRun); err != nil {
			fmt.Printf("[error] auth cleaner check failed: %v\n", err)
			c.logger.WithError(err).Warn("auth cleaner check failed")
		}

		select {
		case <-ctx.Done():
			fmt.Printf("\nAuth cleaner stopped after %d checks\n", loopCount)
			return nil
		case <-time.After(opts.Interval):
		}
	}
}

func (c *Cleaner) RunOnce(ctx context.Context, dryRun bool) (*Summary, error) {
	if c == nil || c.manager == nil {
		return nil, fmt.Errorf("auth cleaner: core manager is unavailable")
	}

	auths := c.manager.List()
	rid := time.Now().UTC().Format("20060102T150405Z")
	backupRoot := filepath.Join("backups", "cliproxyapi-auth-cleaner", rid)
	reportRoot := filepath.Join("reports", "cliproxyapi-auth-cleaner")
	if err := os.MkdirAll(reportRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create report directory: %w", err)
	}

	summary := Summary{}
	results := make([]Result, 0, len(auths))
	fmt.Printf("[%s] checking %d auth files\n", time.Now().Format(time.RFC3339), len(auths))

	for _, auth := range auths {
		if auth == nil {
			continue
		}
		summary.Checked++
		name := strings.TrimSpace(firstNonEmpty(auth.FileName, auth.ID))
		provider := strings.TrimSpace(auth.Provider)
		status := strings.TrimSpace(string(auth.Status))
		statusMessage := strings.TrimSpace(auth.StatusMessage)
		kind, reason := classifyAuth(auth)
		result := Result{
			ID:                  strings.TrimSpace(auth.ID),
			Name:                name,
			Provider:            provider,
			AuthIndex:           strings.TrimSpace(auth.Index),
			Status:              status,
			StatusMessage:       statusMessage,
			FinalClassification: kind,
			Reason:              reason,
		}
		displayReason := displayReason(reason)

		switch kind {
		case "available":
			summary.Available++
		case "quota_exhausted":
			summary.QuotaExceeded++
			fmt.Printf("[quota-exhausted/keep] %s provider=%s reason=%s\n", name, provider, displayReason)
		case "disabled":
			summary.Disabled++
			fmt.Printf("[disabled/keep] %s provider=%s\n", name, provider)
		case "unavailable":
			summary.Unavailable++
			fmt.Printf("[unavailable/keep] %s provider=%s reason=%s\n", name, provider, displayReason)
		case "delete_401":
			summary.Delete401++
			fmt.Printf("[delete-401] %s provider=%s reason=%s\n", name, provider, displayReason)
			if dryRun {
				result.DeleteResult = "dry_run_skip"
				fmt.Println("  [dry-run] would delete this auth file")
				results = append(results, result)
				continue
			}
			if !strings.HasSuffix(strings.ToLower(name), ".json") {
				summary.BackupFailed++
				result.DeleteResult = "skip_no_json_name"
				result.DeleteError = "auth file name does not end with .json"
				fmt.Println("  [skip] auth file name does not end with .json")
				results = append(results, result)
				continue
			}
			backupPath, errDelete := c.backupAndDelete(ctx, auth, backupRoot)
			if errDelete != nil {
				summary.DeleteFailed++
				result.DeleteResult = "delete_failed"
				result.DeleteError = errDelete.Error()
				fmt.Printf("  [delete-failed] %v\n", errDelete)
				results = append(results, result)
				continue
			}
			summary.Deleted++
			result.DeleteResult = "deleted"
			result.BackupPath = backupPath
			fmt.Printf("  [deleted] backup=%s\n", backupPath)
		}
		results = append(results, result)
	}

	report := Report{RunID: rid, DryRun: dryRun, Results: results, Summary: summary, GeneratedAt: time.Now().Format(time.RFC3339)}
	reportPath := filepath.Join(reportRoot, fmt.Sprintf("report-%s.json", rid))
	reportData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(reportPath, reportData, 0o644); err != nil {
		return nil, fmt.Errorf("write report: %w", err)
	}

	printSummary(summary, reportPath, dryRun)
	return &summary, nil
}

func (c *Cleaner) backupAndDelete(ctx context.Context, auth *coreauth.Auth, backupRoot string) (string, error) {
	if auth == nil {
		return "", fmt.Errorf("auth cleaner: auth is nil")
	}
	path := authPath(auth)
	if path == "" {
		return "", fmt.Errorf("auth cleaner: auth %s has no file path", auth.ID)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read auth file for backup: %w", err)
	}
	if err := os.MkdirAll(backupRoot, 0o755); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	backupPath := filepath.Join(backupRoot, filepath.Base(path))
	if err := os.WriteFile(backupPath, raw, 0o600); err != nil {
		return "", fmt.Errorf("write backup file: %w", err)
	}
	if err := c.deleteFn(ctx, auth.ID); err != nil {
		return "", err
	}
	cloned := auth.Clone()
	cloned.Disabled = true
	cloned.Status = coreauth.StatusDisabled
	cloned.StatusMessage = "removed via auth cleaner"
	cloned.UpdatedAt = time.Now()
	if err := c.updateFn(context.Background(), cloned); err != nil {
		return "", err
	}
	return backupPath, nil
}

func (c *Cleaner) defaultDeleteAuth(ctx context.Context, id string) error {
	if c == nil || c.store == nil {
		return fmt.Errorf("auth cleaner: token store unavailable")
	}
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("auth cleaner: auth id is empty")
	}
	return c.store.Delete(ctx, id)
}

func (c *Cleaner) defaultUpdateAuth(ctx context.Context, auth *coreauth.Auth) error {
	if c == nil || c.manager == nil || auth == nil {
		return fmt.Errorf("auth cleaner: invalid update request")
	}
	_, err := c.manager.Update(coreauth.WithSkipPersist(ctx), auth)
	return err
}

func printBanner(opts Options) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("CLIProxyAPI auth cleaner (delete 401 credentials only)")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("Target: auth files with 401/unauthorized authentication failures only")
	fmt.Println("Protected: quota exhausted / disabled / unavailable auths are never deleted")
	if opts.DryRun {
		fmt.Println("Mode: dry-run (no files will be deleted)")
	} else {
		fmt.Println("Mode: live run (matching auth files will be backed up then deleted)")
	}
	if !opts.Once {
		fmt.Printf("Loop interval: %s\n", opts.Interval)
	}
	fmt.Printf("%s\n\n", strings.Repeat("=", 60))
}

func printSummary(summary Summary, reportPath string, dryRun bool) {
	fmt.Printf("\n%s\n", strings.Repeat("=", 60))
	fmt.Println("Summary")
	fmt.Printf("%s\n", strings.Repeat("=", 60))
	fmt.Printf("Checked: %d\n", summary.Checked)
	fmt.Printf("Available: %d\n", summary.Available)
	fmt.Printf("Quota exhausted: %d\n", summary.QuotaExceeded)
	fmt.Printf("Disabled: %d\n", summary.Disabled)
	fmt.Printf("Unavailable: %d\n", summary.Unavailable)
	fmt.Printf("Pending 401 deletions: %d\n", summary.Delete401)
	fmt.Printf("Deleted: %d\n", summary.Deleted)
	fmt.Printf("Backup failed: %d\n", summary.BackupFailed)
	fmt.Printf("Delete failed: %d\n", summary.DeleteFailed)
	fmt.Println()
	if dryRun {
		fmt.Println("Dry-run complete: no auth files were deleted")
	} else if summary.Delete401 == 0 {
		fmt.Println("No 401 auth files matched deletion criteria")
	} else {
		fmt.Printf("Live run complete: deleted %d auth files\n", summary.Deleted)
	}
	fmt.Printf("Report: %s\n", reportPath)
	fmt.Printf("%s\n", strings.Repeat("=", 60))
}

func authPath(auth *coreauth.Auth) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return strings.TrimSpace(auth.Attributes["path"])
}

func extractErrorMessage(msg string) classifiedError {
	msg = strings.TrimSpace(msg)
	if msg == "" || !strings.HasPrefix(msg, "{") {
		return classifiedError{Message: msg}
	}
	var payload jsonError
	if err := json.Unmarshal([]byte(msg), &payload); err != nil {
		return classifiedError{Message: msg}
	}
	if payload.Error.Type == "" && payload.Error.Message == "" {
		return classifiedError{Message: msg}
	}
	return classifiedError{Type: strings.TrimSpace(payload.Error.Type), Message: strings.TrimSpace(payload.Error.Message)}
}

func classifyAuth(auth *coreauth.Auth) (string, string) {
	if auth == nil {
		return "available", "active"
	}
	status := strings.TrimSpace(strings.ToLower(string(auth.Status)))
	msg := strings.TrimSpace(auth.StatusMessage)
	extracted := extractErrorMessage(msg)
	text := strings.ToLower(status + "\n" + msg)

	if pattern401.MatchString(text) {
		return "delete_401", firstNonEmpty(msg, status, "401/unauthorized")
	}
	if strings.EqualFold(extracted.Type, "usage_limit_reached") || strings.Contains(text, "usage_limit_reached") {
		return "quota_exhausted", firstNonEmpty(msg, status, "usage_limit_reached")
	}
	if patternQuota.MatchString(text) {
		return "quota_exhausted", firstNonEmpty(msg, status, "quota")
	}
	if auth.Disabled || status == "disabled" {
		return "disabled", firstNonEmpty(msg, status, "disabled")
	}
	if auth.Unavailable || status == "error" {
		return "unavailable", firstNonEmpty(msg, status, "error")
	}
	return "available", firstNonEmpty(msg, status, "active")
}

func displayReason(reason string) string {
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return "-"
	}
	extracted := extractErrorMessage(reason)
	if extracted.Type == "" && extracted.Message == reason {
		return truncateText(reason, 80)
	}
	if extracted.Type != "" && extracted.Message != "" {
		return truncateText(extracted.Type+": "+extracted.Message, 80)
	}
	return truncateText(firstNonEmpty(extracted.Type, extracted.Message, reason), 80)
}

func truncateText(value string, max int) string {
	value = strings.TrimSpace(value)
	if max <= 0 || len(value) <= max {
		return value
	}
	if max <= 3 {
		return value[:max]
	}
	return value[:max-3] + "..."
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
