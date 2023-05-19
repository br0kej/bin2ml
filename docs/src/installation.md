# Installation

`bin2ml` can be installed by building the source using `cargo`.

```
git clone <REPO_URL>
cd bin2ml
cargo build --release
```

The `bin2ml` will be stored within the `target/release/` directory.

## Experimental Features

`bin2ml` also has experimental features which are either still in active development or still being tested.

In order to activate these, the `--features` flag can be provided to `cargo` during the build process.

For example, if you wanted to activate the `inference` feature which provides support for loading TorchScript PyTorch models, `bin2ml` could be compiled using the following command:
```
cargo build --release --features inference
```