# Wire fixtures for tenant implementations (TOON_Network #16).
#
# `tests/wire_fixtures.rs` generates every file under tests/fixtures/wire/
# from the real HTTP surface and the real event builders, over fixed keys and
# a fixed clock. `cargo test` — and so CI — verifies them byte-for-byte and
# fails on drift. `make fixtures` regenerates them after an intended wire
# change, and syncs the spec repository's copy when TOON_SPEC_DIR points at a
# TOON_Network checkout:
#
#     make fixtures TOON_SPEC_DIR=../TOON_Network
#
# CARGO_TARGET_DIR and the rest of cargo's environment pass through.

FIXTURES := tests/fixtures/wire
SPEC_FIXTURES = $(TOON_SPEC_DIR)/docs/spec/fixtures/wire

.PHONY: fixtures fixtures-check fixtures-sync

## Regenerate tests/fixtures/wire/ from the code, then sync the spec's copy
## if TOON_SPEC_DIR is set. Stale files are removed first, so a renamed
## fixture does not linger.
fixtures:
	rm -f $(FIXTURES)/*.json
	TOON_UPDATE_FIXTURES=1 cargo test --test wire_fixtures
	@if [ -n "$(TOON_SPEC_DIR)" ]; then \
		$(MAKE) fixtures-sync; \
	else \
		echo "regenerated $(FIXTURES); set TOON_SPEC_DIR=<path to TOON_Network> to sync the spec's copy"; \
	fi

## Verify the fixtures against the code without touching them (what CI runs
## as part of `cargo test`).
fixtures-check:
	cargo test --test wire_fixtures

## Copy tests/fixtures/wire/*.json over the spec repository's
## docs/spec/fixtures/wire/, removing anything there that no longer exists.
fixtures-sync:
	@test -n "$(TOON_SPEC_DIR)" || { echo "TOON_SPEC_DIR must point at a TOON_Network checkout" >&2; exit 2; }
	@test -d "$(TOON_SPEC_DIR)/docs/spec" || { echo "$(TOON_SPEC_DIR) has no docs/spec directory" >&2; exit 2; }
	mkdir -p $(SPEC_FIXTURES)
	rm -f $(SPEC_FIXTURES)/*.json
	cp $(FIXTURES)/*.json $(SPEC_FIXTURES)/
	@echo "synced $$(ls $(FIXTURES)/*.json | wc -l) fixtures to $(SPEC_FIXTURES)"
