export RUST_BACKTRACE := "1"
BASE_RUSTFLAGS := "-C force-frame-pointers=y -L " + absolute_path("") / "target/static-libs"
RUSTFLAGS_STATIC := BASE_RUSTFLAGS + " -C target-feature=+crt-static"
RUSTFLAGS_ASAN := BASE_RUSTFLAGS + " -Zsanitizer=address"

build: build-native-libraries
	RUSTFLAGS="{{BASE_RUSTFLAGS}}" cargo build

test: build-native-libraries
	RUSTFLAGS="{{BASE_RUSTFLAGS}}" cargo test

build-release: build-native-libraries
	RUSTFLAGS="{{RUSTFLAGS_STATIC}}" cargo build --release --target x86_64-unknown-linux-gnu

xtask: build-native-libraries
	RUSTFLAGS="{{BASE_RUSTFLAGS}}" cargo xtask

# Note that the native dependencies are not instrumented.
build-asan: build-native-libraries
	RUSTFLAGS="{{RUSTFLAGS_ASAN}}" cargo +nightly build -Zbuild-std --target x86_64-unknown-linux-gnu

test-asan: build-native-libraries
	RUSTFLAGS="{{RUSTFLAGS_ASAN}}" cargo +nightly test -Zbuild-std --target x86_64-unknown-linux-gnu

build-native-libraries:
	./tools/build_deps
