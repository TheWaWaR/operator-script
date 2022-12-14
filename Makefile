
build-debug: contracts/operator-script/src/entry.rs
	capsule build

test-debug: build/debug/operator-script
	CAPSULE_TEST_ENV=debug cargo test --release -p tests

build-release: contracts/operator-script/src/entry.rs
	capsule build --release

test-release: build/release/operator-script
	CAPSULE_TEST_ENV=release cargo test --release -p tests
