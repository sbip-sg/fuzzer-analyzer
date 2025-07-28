# Build Instructions

## Standard Build (with plotting)

For local use with full functionality including plot generation:

```bash
cargo build --release -p ityfuzz-analyzer
```

This requires `libfontconfig` to be installed on the target system.

## Portable Build (without plotting)

For deployment to systems without fontconfig dependencies:

```bash
cargo build --release -p ityfuzz-analyzer --no-default-features
```

This build:
- Removes plotting functionality
- Eliminates fontconfig/freetype dependencies
- Still retains full analysis and CSV export capabilities
- Is more portable across different Linux systems

## Installation

### With plotting support:
```bash
cargo install --path crates/ityfuzz-analyzer/ --profile release --force --locked
```

### Without plotting (portable):
```bash
cargo install --path crates/ityfuzz-analyzer/ --profile release --force --locked --no-default-features
```

## Checking Dependencies

To verify the binary dependencies:
```bash
ldd target/release/ityfuzz-analyzer
```

The portable build should not show any fontconfig or freetype dependencies.

## Usage Notes

When using the portable build:
- The `run` command works normally and generates CSV files
- The `plot` command will show an error message indicating plotting is disabled
- All analysis features remain functional