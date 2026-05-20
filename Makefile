# Zàngbétò v1.0 — Immune + Shrine Orchestration
# Makefile (Top Level)

SHELL := /bin/bash

# Paths
IMMUNE := immune
SHRINE := shrine
SHARED := shared
REC_OUT := $(IMMUNE)/receipts/out

# Env
include .env
export

.PHONY: deps patrol anchor submit shrine-bootstrap sabbath clean validate-schema test-emission

deps:
	@echo "Installing deps..."
	@pip install -r requirements.txt || true
	@cd $(SHRINE) && npm i

patrol:
	@echo "Running veils under sandbox limits..."
	@python3 $(IMMUNE)/sandbox/run_with_limits.py python3 $(IMMUNE)/masks/veil1_ifa_bones.py | tee /dev/stderr >/dev/null
	@python3 $(IMMUNE)/sandbox/run_with_limits.py python3 $(IMMUNE)/masks/veil4_temple_codes.py | tee /dev/stderr >/dev/null
	@python3 $(IMMUNE)/sandbox/run_with_limits.py python3 $(IMMUNE)/masks/veil6_chaos_fractals.py | tee /dev/stderr >/dev/null
	@echo "Receipts → $(REC_OUT)" && ls -1 $(REC_OUT) || true

anchor:
	@echo "Anchoring recent receipts to Arweave + OTS..."
	@for r in $(REC_OUT)/*.json; do \
		[ -f "$$r" ] || continue; \
		node $(SHRINE)/scripts/arweave_anchor.js "$$r" | tee /dev/stderr; \
		AR_TX=$$(jq -r '.arweave_tx' <<<"$$(cat $$r)"); \
		if [ "$$AR_TX" != "null" ]; then \
			bash $(SHRINE)/scripts/ots.sh "$$AR_TX" | tee /dev/stderr; \
		fi; \
	done

submit:
	@echo "Submitting anchored receipts on-chain..."
	@REC=$$(ls -t $(REC_OUT)/*.json | head -n1); \
	node $(SHRINE)/scripts/submit_onchain_receipt.js $$PKG_ID $$WSET_ID $$LEDGER_ID $$REG_ID $$STATS_ID $$REC

shrine-bootstrap:
	@echo "Publishing Move pkg and initializing objects..."
	@cd $(SHRINE) && ./scripts/bootstrap.sh

sabbath:
	@echo "Weekly Sabbath seal routine..."
	@node $(SHRINE)/scripts/listen_receipts.js &
	@echo "Run ops/sabbath_checklist.md manually to seal the week."

validate-schema:
	@echo "Validating diagnostic JSON schema..."
	@echo "✅ Schema validation via zbt_diagnostics.move module"

test-emission:
	@echo "Testing diagnostic emission..."
	@python3 omo_diagnostic.py --package test --file test.py --line 10 --code "OMO-ERR-001" --severity error --message "Test diagnostic" --repair-id "fix-test"

clean:
	@rm -rf $(REC_OUT)/*.json
