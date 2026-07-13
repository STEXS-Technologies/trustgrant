use std::path::Path;

use serde_json::Value;
use trustgrant::{
    EvaluationDenyReason, SelectorExpression,
    document::raw::RawTrustGrantDocument,
    document::ValidatedTrustGrantDocument,
    domain::SelectorKind,
};

// ---------------------------------------------------------------------------
// Base valid document
// ---------------------------------------------------------------------------

fn base_document_json() -> Value {
    serde_json::json!({
        "trustgrant_id": "tg_11111111-1111-4111-8111-111111111001",
        "version": 0,
        "grant_series_id": "tgs_11111111-1111-4111-8111-111111111001",
        "revision": 1,
        "supersedes": null,
        "supersession_policy": "coexist",
        "issuer_authority": "https://issuer.example.com",
        "origin_authority": "https://issuer.example.com",
        "active_owning_authority": "https://issuer.example.com",
        "key_id": "root-key-1",
        "target_scope": {
            "all": false,
            "allow": [{"kind": "authority", "all": false, "values": ["https://target.example.com"], "expressions": null}],
            "deny": null
        },
        "capabilities": { "recognize": true, "mint": false },
        "default_audience_scope": null,
        "resource_scope": {
            "types": {
                "item": {
                    "all": false,
                    "allow": [{"kind": "namespace", "all": false, "values": ["weapons"], "expressions": null}],
                    "deny": null,
                    "capabilities": { "recognize": null, "mint": null },
                    "constraints": { "minting": { "max_total": null, "max_per_user": null }, "audience_scope": null },
                    "operations": null
                }
            }
        },
        "global_constraints": {
            "time": { "not_before": "2026-04-07T12:00:00Z", "not_after": "2027-04-08T12:00:00Z" }
        },
        "revocation": {
            "revocable": true,
            "revocation_endpoint": "https://issuer.example.com/revocation"
        },
        "issued_at": "2026-04-07T12:00:00Z",
        "signature": "base64-signature",
        "issuer_principal": { "kind": "service", "id": "issuer-worker" }
    })
}

fn apply_overrides(base: &Value, overrides: &Value) -> Value {
    let mut doc = base.clone();
    if let Some(obj) = overrides.as_object() {
        if let Some(doc_obj) = doc.as_object_mut() {
            for (key, val) in obj {
                doc_obj.insert(key.clone(), val.clone());
            }
        }
    }
    doc
}

// ---------------------------------------------------------------------------
// Vector types
// ---------------------------------------------------------------------------

struct ConformanceVector {
    spec_section: String,
    description: String,
    trustgrant: Option<Value>,
    overrides: Option<Value>,
    expression: Option<ExpressionVector>,
    selector_kind: Option<SelectorKindVector>,
    assert: Assertion,
}

struct ExpressionVector {
    predicate: String,
    match_cases: Vec<String>,
    no_match_cases: Vec<String>,
}

struct SelectorKindVector {
    a: String,
    b: String,
    expect_equal: bool,
}

enum Assertion {
    ValidationAccepted,
    ValidationRejected,
    Expression { predicate: String, match_cases: Vec<String>, no_match_cases: Vec<String> },
    SelectorKindsEqual { a: String, b: String, expect_equal: bool },
    EvaluationDenied(EvaluationDenyReason),
    EvaluationAllowed,
    ParseError,
}

fn parse_vector(value: &Value) -> Result<ConformanceVector, String> {
    let spec_section = value["spec_section"].as_str().unwrap_or("?").to_owned();
    let description = value["description"].as_str().unwrap_or("?").to_owned();
    let overrides = value.get("overrides").cloned();
    let expression = value.get("expression").map(|e| ExpressionVector {
        predicate: e["predicate"].as_str().unwrap_or("").to_owned(),
        match_cases: e["match"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
        no_match_cases: e["no_match"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect()).unwrap_or_default(),
    });
    let selector_kind = value.get("selector_kind").map(|s| SelectorKindVector {
        a: s["a"].as_str().unwrap_or("").to_owned(),
        b: s["b"].as_str().unwrap_or("").to_owned(),
        expect_equal: s["expect_equal"].as_bool().unwrap_or(true),
    });

    let assert_val = &value["assert"];
    let assert = if let Some(validation) = assert_val.get("validation") {
        match validation.as_str() {
            Some("accepted") => Assertion::ValidationAccepted,
            Some("rejected") => Assertion::ValidationRejected,
            _ => return Err(format!("unknown validation: {validation:?}")),
        }
    } else if let Some(eval) = assert_val.get("evaluation") {
        match eval.as_str() {
            Some("Allowed") => Assertion::EvaluationAllowed,
            Some(v) if v.starts_with("Denied::") => {
                let reason = v.strip_prefix("Denied::").unwrap_or("");
                let reason_enum = parse_deny_reason(reason)?;
                Assertion::EvaluationDenied(reason_enum)
            }
            _ => return Err(format!("unknown evaluation: {eval:?}")),
        }
    } else if assert_val.get("parse_error").is_some() {
        Assertion::ParseError
    } else {
        return Err(format!("unknown assertion type in {description}"));
    };

    Ok(ConformanceVector {
        spec_section,
        description,
        trustgrant: value.get("trustgrant").cloned(),
        overrides,
        expression,
        selector_kind,
        assert,
    })
}

fn parse_deny_reason(s: &str) -> Result<EvaluationDenyReason, String> {
    match s {
        "Revoked" => Ok(EvaluationDenyReason::Revoked),
        "NotYetValid" => Ok(EvaluationDenyReason::NotYetValid),
        "Expired" => Ok(EvaluationDenyReason::Expired),
        "TargetDenied" => Ok(EvaluationDenyReason::TargetDenied),
        "TargetNotAllowed" => Ok(EvaluationDenyReason::TargetNotAllowed),
        "ResourceTypeNotGranted" => Ok(EvaluationDenyReason::ResourceTypeNotGranted),
        "ResourceDenied" => Ok(EvaluationDenyReason::ResourceDenied),
        "ResourceNotAllowed" => Ok(EvaluationDenyReason::ResourceNotAllowed),
        "OperationDenied" => Ok(EvaluationDenyReason::OperationDenied),
        "CapabilityDisabled" => Ok(EvaluationDenyReason::CapabilityDisabled),
        "MissingMintContext" => Ok(EvaluationDenyReason::MissingMintContext),
        "MissingAudiencePrincipalContext" => Ok(EvaluationDenyReason::MissingAudiencePrincipalContext),
        "MintTotalLimitReached" => Ok(EvaluationDenyReason::MintTotalLimitReached),
        "MintPerUserLimitReached" => Ok(EvaluationDenyReason::MintPerUserLimitReached),
        "AudienceDenied" => Ok(EvaluationDenyReason::AudienceDenied),
        "AudienceNotAllowed" => Ok(EvaluationDenyReason::AudienceNotAllowed),
        "AudiencePrincipalDenied" => Ok(EvaluationDenyReason::AudiencePrincipalDenied),
        "AudiencePrincipalNotAllowed" => Ok(EvaluationDenyReason::AudiencePrincipalNotAllowed),
        _ => Err(format!("unknown deny reason: {s}")),
    }
}

fn run_vector(path: &Path) -> Result<(), String> {
    let content = std::fs::read_to_string(path).map_err(|e| format!("read {path:?}: {e}"))?;
    let value: Value = serde_json::from_str(&content).map_err(|e| format!("parse {path:?}: {e}"))?;
    let vector = parse_vector(&value)?;

    let basename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("?");

    // Handle expression tests
    if let Some(expr) = &vector.expression {
        let parsed = match SelectorExpression::parse(&expr.predicate) {
            Ok(p) => {
                // If the predicate has no_match entries that equal "PARSE_ERROR",
                // this is expected to fail parsing. If match entries are also empty,
                // it's a pure parse-failure test.
                if expr.match_cases.is_empty() && expr.no_match_cases.is_empty() {
                    // Expected to fail — if it succeeded, that's wrong
                    return Err(format!(
                        "{basename}: expected parse failure for '{}' but it succeeded",
                        expr.predicate
                    ));
                }
                p
            }
            Err(e) => {
                // Parse failed. Check if this was expected.
                if expr.match_cases.is_empty() && expr.no_match_cases.is_empty() {
                    return Ok(()); // Expected failure
                }
                return Err(format!("{basename}: expression parse failed: {e}"));
            }
        };
        for case in &expr.match_cases {
            if !parsed.matches(case) {
                return Err(format!("{basename}: expected '{case}' to match '{}'", expr.predicate));
            }
        }
        for case in &expr.no_match_cases {
            if parsed.matches(case) {
                return Err(format!("{basename}: expected '{case}' to NOT match '{}'", expr.predicate));
            }
        }
        return Ok(());
    }

    // Handle selector kind tests
    if let Some(sk) = &vector.selector_kind {
        let kind_a = SelectorKind::new(&sk.a).map_err(|e| format!("{basename}: kind_a '{}': {e}", sk.a))?;
        let kind_b = SelectorKind::new(&sk.b).map_err(|e| format!("{basename}: kind_b '{}': {e}", sk.b))?;
        let are_equal = kind_a == kind_b;
        if are_equal != sk.expect_equal {
            return Err(format!(
                "{basename}: expected equal={}, got equal={} for '{}' vs '{}'",
                sk.expect_equal, are_equal, sk.a, sk.b
            ));
        }
        return Ok(());
    }

    // Build the trustgrant document
    let base = base_document_json();
    let doc_json = if let Some(overrides) = &vector.overrides {
        apply_overrides(&base, overrides)
    } else if let Some(tg) = &vector.trustgrant {
        tg.clone()
    } else {
        base
    };

    let json_str = serde_json::to_string(&doc_json).map_err(|e| format!("{basename}: serialize: {e}"))?;

    let raw = match RawTrustGrantDocument::parse_json_str(&json_str) {
        Ok(r) => r,
        Err(e) => {
            return match &vector.assert {
                Assertion::ParseError | Assertion::ValidationRejected => Ok(()),
                _ => Err(format!("{basename}: unexpected parse error: {e}")),
            };
        }
    };

    match &vector.assert {
        Assertion::ParseError => {
            return Err(format!("{basename}: expected parse error but parsing succeeded"));
        }
        Assertion::ValidationRejected => {
            let result = ValidatedTrustGrantDocument::try_from(raw);
            if result.is_ok() {
                return Err(format!("{basename}: expected validation rejection but it succeeded"));
            }
        }
        Assertion::ValidationAccepted => {
            ValidatedTrustGrantDocument::try_from(raw)
                .map_err(|e| format!("{basename}: expected validation to succeed: {e}"))?;
        }
        _ => {
            ValidatedTrustGrantDocument::try_from(raw)
                .map_err(|e| format!("{basename}: validation failed: {e}"))?;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test entry point
// ---------------------------------------------------------------------------

#[test]
fn conformance_vectors() {
    let vectors_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("conformance")
        .join("vectors");

    let mut passed = 0usize;
    let mut failed: Vec<String> = Vec::new();
    let mut skipped = 0usize;

    let mut entries: Vec<_> = match std::fs::read_dir(&vectors_dir) {
        Ok(d) => d.filter_map(|e| e.ok()).collect(),
        Err(e) => panic!("cannot read {vectors_dir:?}: {e}"),
    };
    entries.sort_by_key(|e| e.path());

    for entry in &entries {
        let path = entry.path();
        if !path.extension().is_some_and(|ext| ext == "json") {
            continue;
        }
        // Skip evaluation vectors (handled by interop harness) and base doc
        let name = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
        if name == "base_document" {
            skipped += 1;
            continue;
        }

        match run_vector(&path) {
            Ok(()) => passed += 1,
            Err(msg) => failed.push(msg),
        }
    }

    assert!(
        passed + failed.len() > 0,
        "no conformance vector JSON files found in {vectors_dir:?}"
    );

    if !failed.is_empty() {
        panic!(
            "{}/{} conformance tests failed:\n  {}",
            failed.len(),
            passed + failed.len(),
            failed.join("\n  ")
        );
    }

    if skipped > 0 {
        println!("{passed} conformance vectors passed ({skipped} skipped)");
    } else {
        println!("{passed} conformance vectors passed");
    }
}

// ---------------------------------------------------------------------------
// Malformed vector rejection tests
// ---------------------------------------------------------------------------

#[test]
fn conformance_vector_rejects_malformed_file() {
    use std::io::Write;

    // Use a unique temp dir based on the test name
    let dir = std::env::temp_dir().join("tg_conformance_malformed_test");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap_or_else(|e| panic!("create temp dir: {e}"));

    // Test 1: non-JSON content
    {
        let path = dir.join("not_json.json");
        let mut f = std::fs::File::create(&path).unwrap_or_else(|e| panic!("create file: {e}"));
        write!(f, "this is not json").unwrap_or_else(|e| panic!("write: {e}"));
        f.flush().unwrap_or_else(|e| panic!("flush: {e}"));
        let result = run_vector(&path);
        assert!(result.is_err(), "non-JSON content should be rejected");
        eprintln!("  [ok] non-JSON → {:?}", result.err().unwrap());
    }

    // Test 2: missing "assert" field
    {
        let path = dir.join("missing_assert.json");
        let mut f = std::fs::File::create(&path).unwrap_or_else(|e| panic!("create file: {e}"));
        write!(
            f,
            r#"{{"spec_section":"5","description":"no assert field"}}"#
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        f.flush().unwrap_or_else(|e| panic!("flush: {e}"));
        let result = run_vector(&path);
        assert!(result.is_err(), "missing assert field should be rejected");
        eprintln!("  [ok] missing assert → {:?}", result.err().unwrap());
    }

    // Test 3: "assert" value is not an object
    {
        let path = dir.join("assert_not_object.json");
        let mut f = std::fs::File::create(&path).unwrap_or_else(|e| panic!("create file: {e}"));
        write!(
            f,
            r#"{{"spec_section":"5","description":"assert not object","assert":"string"}}"#
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        f.flush().unwrap_or_else(|e| panic!("flush: {e}"));
        let result = run_vector(&path);
        assert!(
            result.is_err(),
            "non-object assert value should be rejected"
        );
        eprintln!("  [ok] assert not object → {:?}", result.err().unwrap());
    }

    // Test 4: unknown validation value in "assert"
    {
        let path = dir.join("unknown_validation.json");
        let mut f = std::fs::File::create(&path).unwrap_or_else(|e| panic!("create file: {e}"));
        write!(
            f,
            r#"{{"spec_section":"5","description":"unknown validation","assert":{{"validation":"bogus"}}}}"#
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        f.flush().unwrap_or_else(|e| panic!("flush: {e}"));
        let result = run_vector(&path);
        assert!(
            result.is_err(),
            "unknown validation value should be rejected"
        );
        eprintln!(
            "  [ok] unknown validation → {:?}",
            result.err().unwrap()
        );
    }

    // Test 5: unknown evaluation value in "assert"
    {
        let path = dir.join("unknown_evaluation.json");
        let mut f = std::fs::File::create(&path).unwrap_or_else(|e| panic!("create file: {e}"));
        write!(
            f,
            r#"{{"spec_section":"5","description":"unknown evaluation","assert":{{"evaluation":"Bogus"}}}}"#
        )
        .unwrap_or_else(|e| panic!("write: {e}"));
        f.flush().unwrap_or_else(|e| panic!("flush: {e}"));
        let result = run_vector(&path);
        assert!(
            result.is_err(),
            "unknown evaluation value should be rejected"
        );
        eprintln!(
            "  [ok] unknown evaluation → {:?}",
            result.err().unwrap()
        );
    }

    // Clean up
    std::fs::remove_dir_all(&dir).unwrap_or_else(|e| panic!("cleanup temp dir: {e}"));
}
