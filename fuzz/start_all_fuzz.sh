#!/bin/bash
# Start all 16 fuzz targets for 24h in background
# Each logs to its own file in fuzz/

FUZZ_DIR="/home/ac/projects/trustgrant/fuzz"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
DURATION=86400  # 24h in seconds

TARGETS=(
  fuzz_authority_id
  fuzz_bundle_proof_parse
  fuzz_canonicalize
  fuzz_delegated_principal_parse
  fuzz_discovery_parse
  fuzz_draft_serialize
  fuzz_evaluation_engine
  fuzz_ownership_chain_verify
  fuzz_ownership_transition_parse
  fuzz_ownership_transition_verify
  fuzz_revocation_proof_parse
  fuzz_selector_expression_parse
  fuzz_selector_kind
  fuzz_trustgrant_document_parse
  fuzz_trustgrant_document_validate
  fuzz_verification_pipeline
)

echo "Starting ${#TARGETS[@]} fuzz targets at $(date)"
echo "Duration: ${DURATION}s (24h)"
echo ""

PIDS=()
for target in "${TARGETS[@]}"; do
  LOGFILE="${FUZZ_DIR}/${target}.${TIMESTAMP}.log"
  echo "Starting $target -> $(basename $LOGFILE)"
  nohup nice -n 19 cargo +nightly-2026-06-01 fuzz run "$target" -- \
    -max_total_time=$DURATION \
    -artifact_prefix="${FUZZ_DIR}/artifacts/${target}/" \
    > "$LOGFILE" 2>&1 &
  PIDS+=($!)
done

echo ""
echo "All targets launched. PIDs: ${PIDS[*]}"
echo "Monitor with: tail -f fuzz/<target>.<TIMESTAMP>.log"
echo "Kill all with: kill ${PIDS[*]}"
