package demoapp

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/umai-protocol/umai/pkg/umaispool"
)

// DocumentInfo describes a sample document stored in the demo application's local documents directory.
type DocumentInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	SHA256  string    `json:"sha256,omitempty"`
}

// DocStore manages the demo application's local document workspace (<dataDir>/docs/),
// completely decoupled from pkg/umaispool's outbox/inbox spool directories.
type DocStore struct {
	mu            sync.RWMutex
	docsDir       string
	stagingDir    string
	maxUploadSize int64
}

// NewDocStore initializes <dataDir>/docs/ and its private staging folder (<dataDir>/.docs-staging/).
func NewDocStore(dataDir string, maxUploadSize int64) (*DocStore, error) {
	absDataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolving data directory: %w", err)
	}
	if maxUploadSize <= 0 {
		maxUploadSize = 100 * 1024 * 1024
	}
	docsDir := filepath.Join(absDataDir, "docs")
	stagingDir := filepath.Join(absDataDir, ".docs-staging")

	_ = os.RemoveAll(stagingDir)
	for _, dir := range []string{docsDir, stagingDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("creating directory %s: %w", dir, err)
		}
	}

	return &DocStore{
		docsDir:       docsDir,
		stagingDir:    stagingDir,
		maxUploadSize: maxUploadSize,
	}, nil
}

// ListDocuments lists all regular files in docsDir.
func (ds *DocStore) ListDocuments() ([]DocumentInfo, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	entries, err := os.ReadDir(ds.docsDir)
	if err != nil {
		return nil, err
	}

	var docs []DocumentInfo
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == ".DS_Store" {
			continue
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		docs = append(docs, DocumentInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime().UTC(),
		})
	}
	return docs, nil
}

// SaveDocument atomically writes an uploaded document into docsDir.
func (ds *DocStore) SaveDocument(filename string, r io.Reader) (*DocumentInfo, error) {
	cleanName, err := umaispool.SanitizeFilename(filename)
	if err != nil {
		return nil, err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	targetPath := filepath.Join(ds.docsDir, cleanName)
	nameHash := sha256.Sum256([]byte(cleanName))
	tmpPath := filepath.Join(ds.stagingDir, fmt.Sprintf("doc-%s-%d", hex.EncodeToString(nameHash[:8]), time.Now().UTC().UnixNano()))

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	limitReader := io.LimitReader(r, ds.maxUploadSize+1)
	writer := io.MultiWriter(f, hasher)

	n, err := io.Copy(writer, limitReader)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if n > ds.maxUploadSize {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, umaispool.ErrFileTooLarge
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := umaispool.SyncDir(ds.stagingDir); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, err
	}
	if err := umaispool.SyncDir(ds.docsDir); err != nil {
		return nil, err
	}

	return &DocumentInfo{
		Name:    cleanName,
		Size:    n,
		ModTime: time.Now().UTC(),
		SHA256:  hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

// GetDocumentPath returns the validated path of a regular document file in docsDir.
func (ds *DocStore) GetDocumentPath(filename string) (string, error) {
	cleanName, err := umaispool.SanitizeFilename(filename)
	if err != nil {
		return "", err
	}

	ds.mu.RLock()
	defer ds.mu.RUnlock()

	targetPath := filepath.Join(ds.docsDir, cleanName)
	if fi, err := os.Lstat(targetPath); err != nil || !fi.Mode().IsRegular() {
		return "", umaispool.ErrNotFound
	}
	return targetPath, nil
}

// DeleteDocument removes a document from docsDir.
func (ds *DocStore) DeleteDocument(filename string) error {
	cleanName, err := umaispool.SanitizeFilename(filename)
	if err != nil {
		return err
	}

	ds.mu.Lock()
	defer ds.mu.Unlock()

	targetPath := filepath.Join(ds.docsDir, cleanName)
	if err := os.Remove(targetPath); err != nil {
		if os.IsNotExist(err) {
			return umaispool.ErrNotFound
		}
		return err
	}
	return nil
}
