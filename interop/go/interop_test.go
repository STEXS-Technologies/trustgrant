package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Vector types (mirrors Rust test vector format) ---

type TestVector struct {
	Description        string           `json:"description"`
	TrustGrant         json.RawMessage  `json:"trustgrant"`
	RevocationOverride string           `json:"revocation_override"`
	Evaluations        []EvaluationItem `json:"evaluations"`
}

type EvaluationItem struct {
	Description string          `json:"description"`
	Request     json.RawMessage `json:"request"`
	Expected    json.RawMessage `json:"expected"`
	Setup       string          `json:"setup"`
}

// --- Helpers ---

// vectorsDir returns the absolute path to the interop test vectors.
// Walks up from the test binary to find the project root.
func vectorsDir() (string, error) {
	// Try several possible relative paths from the test working directory
	candidates := []string{
		"../../tests/interop/vectors", // when run from interop/go/
		"../tests/interop/vectors",    // from project root
		"tests/interop/vectors",       // from project root (alt)
	}
	for _, c := range candidates {
		abs, err := filepath.Abs(c)
		if err != nil {
			continue
		}
		if info, err := os.Stat(abs); err == nil && info.IsDir() {
			return abs, nil
		}
	}
	return "", fmt.Errorf("cannot find vectors directory (tried %v)", candidates)
}

func loadVectors(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths, nil
}

// --- Tests ---

func TestInteropVectorsParse(t *testing.T) {
	dir, err := vectorsDir()
	if err != nil {
		t.Fatal(err)
	}

	paths, err := loadVectors(dir)
	if err != nil {
		t.Fatal(err)
	}

	if len(paths) == 0 {
		t.Fatal("no vector JSON files found")
	}

	var passed, failed int

	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("cannot read %s: %v", path, err)
			failed++
			continue
		}

		var vec TestVector
		if err := json.Unmarshal(data, &vec); err != nil {
			t.Errorf("invalid JSON in %s: %v", path, err)
			failed++
			continue
		}

		if vec.Description == "" {
			t.Errorf("%s: missing description", path)
			failed++
			continue
		}

		if len(vec.TrustGrant) == 0 {
			t.Errorf("%s: missing trustgrant document", path)
			failed++
			continue
		}

		// Verify the trustgrant document has the required fields
		var doc map[string]json.RawMessage
		if err := json.Unmarshal(vec.TrustGrant, &doc); err != nil {
			t.Errorf("%s: trustgrant is not valid JSON: %v", path, err)
			failed++
			continue
		}

		requiredFields := []string{
			"trustgrant_id", "version", "grant_series_id", "revision",
			"issuer_authority", "origin_authority", "active_owning_authority",
			"key_id", "target_scope", "capabilities", "resource_scope",
			"issued_at", "signature",
		}
		for _, f := range requiredFields {
			if _, ok := doc[f]; !ok {
				t.Errorf("%s: trustgrant missing required field %q", filepath.Base(path), f)
				failed++
			}
		}

		// Verify the version is 0
		var version float64
		if v, ok := doc["version"]; ok {
			json.Unmarshal(v, &version)
			if version != 0 {
				t.Errorf("%s: version must be 0, got %v", filepath.Base(path), version)
				failed++
			}
		}

		// Validate revocation_override if present
		if vec.RevocationOverride != "" &&
			vec.RevocationOverride != "revoked" &&
			vec.RevocationOverride != "non_revocable" {
			t.Errorf("%s: invalid revocation_override %q (must be revoked, non_revocable, or absent)",
				filepath.Base(path), vec.RevocationOverride)
			failed++
		}

		// Check evaluations are parseable (assertions are pending Go impl)
		for i, eval := range vec.Evaluations {
			if eval.Description == "" {
				t.Errorf("%s: evaluation %d missing description", filepath.Base(path), i)
				failed++
			}
			if len(eval.Request) == 0 {
				t.Errorf("%s: evaluation %d missing request", filepath.Base(path), i)
				failed++
			}
			if len(eval.Expected) == 0 {
				t.Errorf("%s: evaluation %d missing expected", filepath.Base(path), i)
				failed++
			}
			// Verify expected is either a string "Allowed" or {"Denied": "..."}
			var allowed string
			if err := json.Unmarshal(eval.Expected, &allowed); err != nil {
				var denied struct {
					Denied string `json:"Denied"`
				}
				if err2 := json.Unmarshal(eval.Expected, &denied); err2 != nil || denied.Denied == "" {
					t.Errorf("%s: evaluation %d: expected must be \"Allowed\" or {\"Denied\":\"...\"}",
						filepath.Base(path), i)
					failed++
				}
			}
			// Validate setup field if present
			if eval.Setup != "" && eval.Setup != "add_audience_principal" {
				t.Errorf("%s: evaluation %d: invalid setup %q",
					filepath.Base(path), i, eval.Setup)
				failed++
			}
		}

		if failed == 0 {
			passed++
		}
	}

	if failed > 0 {
		t.Fatalf("%d/%d interop vectors have structural issues", failed, passed+failed)
	}

	fmt.Printf("ok  %d interop vectors parsed and validated\n", passed)

	// Print summary of what evaluations would be tested
	fmt.Println("\nEvaluation scenarios (pending Go TrustGrant implementation):")
	for _, path := range paths {
		data, _ := os.ReadFile(path)
		var vec TestVector
		json.Unmarshal(data, &vec)
		for _, eval := range vec.Evaluations {
			fmt.Printf("  • %s: %s\n", vec.Description, eval.Description)
		}
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
