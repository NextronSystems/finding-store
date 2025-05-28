package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/NextronSystems/jsonlog/thorlog/parser"
	"github.com/NextronSystems/jsonlog/thorlog/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLayout(t *testing.T) {
	rootDir := t.TempDir()
	layout := New(rootDir)

	finding := thorlog.NewFinding(thorlog.NewFile("test.txt"), "Test finding")
	finding.Meta = thorlog.LogEventMetadata{
		GenID: "abcdef1234567890",
		Time:  time.Now(),
		Lvl:   thorlog.Alert,
	}
	var content = []byte("This is a test content for the finding.")
	sha256Hash := sha256.Sum256(content)
	if err := layout.Store(finding, bytes.NewReader(content)); err != nil {
		t.Fatalf("Failed to store finding: %v", err)
	}
	hashString := hex.EncodeToString(sha256Hash[:])

	readFinding, contentHash, err := layout.LoadFinding("abcdef1234567890")
	require.NoError(t, err)
	assert.Equal(t, contentHash, hashString)
	assert.NotNil(t, readFinding)
	assert.Equal(t, finding.Meta.GenID, readFinding.Meta.GenID)
	assert.Equal(t, finding.Subject.(*thorlog.File).Path, "test.txt")

	loadedContent, findings, err := layout.LoadContent(hashString)
	require.NoError(t, err)
	assert.Equal(t, content, loadedContent)
	assert.Len(t, findings, 1)
	assert.Equal(t, findings[0].Meta.GenID, readFinding.Meta.GenID)
}

func (s *Store) LoadFinding(id string) (*thorlog.Finding, string, error) {
	if len(id) < 2 {
		return nil, "", fmt.Errorf("finding ID is too short, must be at least 2 characters: %s", id)
	}
	path := s.path(subdirFindings, id)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", fmt.Errorf("cannot read finding data: %w", err)
	}
	event, err := parser.ParseEvent(data)
	if err != nil {
		return nil, "", fmt.Errorf("cannot unmarshal finding data: %w", err)
	}
	finding, ok := event.(*thorlog.Finding)
	if !ok {
		return nil, "", fmt.Errorf("data is not a valid finding: %s", id)
	}
	hash, err := os.ReadFile(path + suffixHash)
	if err != nil {
		if os.IsNotExist(err) {
			return finding, "", nil // No content hash found, return finding without content.
		}
		return nil, "", fmt.Errorf("cannot read content hash: %w", err)
	}
	return finding, string(hash), nil
}

func (s *Store) LoadContent(hash string) ([]byte, []*thorlog.Finding, error) {
	if len(hash) < 2 {
		return nil, nil, fmt.Errorf("content hash is too short, must be at least 2 characters: %s", hash)
	}
	path := s.path(subdirContent, hash)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read content data: %w", err)
	}
	// Read the metadata file to get the list of findings that reference this content.
	metadataFile, err := os.Open(path + suffixMetadata)
	if err != nil {
		return data, nil, fmt.Errorf("cannot read content metadata: %w", err)
	}
	defer func() {
		_ = metadataFile.Close()
	}()
	var findings []*thorlog.Finding
	reader := bufio.NewScanner(metadataFile)
	for reader.Scan() {
		event, err := parser.ParseEvent(reader.Bytes())
		if err != nil {
			return nil, nil, fmt.Errorf("cannot parse finding metadata: %w", err)
		}
		finding, ok := event.(*thorlog.Finding)
		if !ok {
			return nil, nil, fmt.Errorf("metadata is not a valid finding: %s", string(reader.Bytes()))
		}
		findings = append(findings, finding)
	}
	return data, findings, nil
}
