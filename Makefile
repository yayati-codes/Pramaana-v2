# Pramaana monorepo. `make setup` once, then `make build`.
export PATH := $(HOME)/.foundry/bin:$(PATH)

.PHONY: build rust-build contracts-build js-install setup check-ts test clean

build: rust-build contracts-build js-install

rust-build:
	cargo build

contracts-build:
	forge build --root contracts

js-install:
	pnpm install

setup:
	bash scripts/setup-toolchain.sh

# Typecheck the TS workspace (sdk must be built so app resolves its types).
check-ts: js-install
	pnpm --filter @pramaana/sdk build
	pnpm -r run check

test:
	cargo test
	forge test --root contracts

clean:
	cargo clean
	forge clean --root contracts
	rm -rf node_modules sdk/node_modules sdk/dist app/node_modules app/dist circuits/node_modules circuits/build
