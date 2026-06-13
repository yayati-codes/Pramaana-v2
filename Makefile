# Pramaana monorepo. `make setup` once, then `make build`.
export PATH := $(HOME)/.foundry/bin:$(PATH)

.PHONY: build rust-build contracts-build js-install setup check-ts test demo clean

build: rust-build contracts-build js-install

rust-build:
	cargo build

contracts-build:
	forge build --root contracts

js-install:
	pnpm install

setup:
	bash scripts/setup-toolchain.sh

# Typecheck the TS workspace (semaphore + sdk must be built so dependents
# resolve their types).
check-ts: js-install
	pnpm --filter @pramaana/semaphore build
	pnpm --filter @pramaana/sdk build
	pnpm -r run check

test:
	cargo test
	forge test --root contracts
	pnpm -r --if-present run test

# Headless end-to-end demo: brings up anvil + voprf-vault + enrollment-tee
# (sim), runs enroll → prove → claim, and asserts Sybil resistance +
# unlinkability. The script cargo-builds the Rust binaries and forge-builds
# the contracts itself, so this works from a clean checkout. Exits non-zero
# on failure. (Interactive browser version: `pnpm --filter @pramaana/app demo`.)
demo: js-install
	pnpm --filter @pramaana/semaphore build
	pnpm --filter @pramaana/sdk build
	pnpm --filter @pramaana/app build
	node app/dist/e2e-demo.js

clean:
	cargo clean
	forge clean --root contracts
	rm -rf node_modules sdk/node_modules sdk/dist app/node_modules app/dist circuits/node_modules circuits/build
