package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
)

func New(root string) *Store {
	return &Store{
		RootDir: root,
		Flat:    false,
	}
}

type Store struct {
	RootDir string
	Flat    bool
}

const (
	subdirFindings = "findings"
	subdirContent  = "samples"
	suffixMetadata = ".metadata"
	suffixHash     = ".hash"
)

func (s *Store) Store(finding *thorlog.Finding, content io.ReadSeeker) error {
	findingId := finding.Meta.GenID
	if findingId == "" {
		return fmt.Errorf("finding ID is empty, cannot store finding")
	} else if len(findingId) < 2 {
		return fmt.Errorf("finding ID is too short, must be at least 2 characters: %s", findingId)
	}
	var contentHash string
	if content != nil {
		// Shortcut: if the content is already hashed, we can use it directly.
		if file, isFile := finding.Subject.(*thorlog.File); isFile && file.Hashes != nil {
			contentHash = file.Hashes.Sha256
		} else {
			hash := sha256.New()
			if _, err := io.Copy(hash, content); err != nil {
				return fmt.Errorf("could not hash content: %w", err)
			}
			contentHash = hex.EncodeToString(hash.Sum(nil))
			// Reset the content reader to the beginning for later use.
			if _, err := content.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("cannot reset content reader: %w", err)
			}
		}
	}
	findingJson, err := json.Marshal(finding)
	if err != nil {
		return fmt.Errorf("cannot marshal finding: %w", err)
	}
	if err := s.storeData(subdirFindings, findingId, bytes.NewReader(findingJson), false); err != nil {
		return fmt.Errorf("cannot store finding data: %w", err)
	}
	if content != nil {
		if err := s.storeData(subdirContent, contentHash, content, false); err != nil {
			if !os.IsExist(err) { // If the content already exists, we can ignore the error.
				return fmt.Errorf("cannot store content data: %w", err)
			}
		}
		// Store cross-references: Finding ID -> content hash, and content hash -> finding metadata.
		// A finding can have only one content hash, but a content hash can be referenced by multiple findings.
		if err := s.storeData(subdirFindings, findingId+suffixHash, strings.NewReader(contentHash), false); err != nil {
			return fmt.Errorf("cannot store content hash for finding: %w", err)
		}
		if err := s.storeData(subdirContent, contentHash+suffixMetadata, bytes.NewReader(append(findingJson, '\n')), true); err != nil {
			return fmt.Errorf("cannot store content metadata: %w", err)
		}
	}
	return nil
}

func (s *Store) storeData(subdir string, id string, data io.Reader, append bool) error {
	path := s.path(subdir, id)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("cannot create directory: %w", err)
	}
	var openFlags = os.O_WRONLY | os.O_CREATE
	if append {
		openFlags |= os.O_APPEND
	} else {
		openFlags |= os.O_EXCL
	}
	file, err := os.OpenFile(path, openFlags, 0644)
	if err != nil {
		return fmt.Errorf("cannot create file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err := io.Copy(file, data); err != nil {
		return fmt.Errorf("cannot write to file: %w", err)
	}
	return nil
}

func (s *Store) path(subdir string, id string) string {
	if s.Flat {
		return filepath.Join(s.RootDir, subdir, id)
	}
	return filepath.Join(s.RootDir, subdir, id[:2], id)
}
