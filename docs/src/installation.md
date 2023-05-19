# Installation

`bin2ml` can be installed by building the source using `cargo`.

```
git clone <REPO_URL>
cd bin2ml
cargo build --release
```

The `bin2ml` will be stored within the `target/release/` directory.

## Pre-Requisites
`bin2ml` relies heavily on Radare2 for the binary analysis tasks and therefore expects that radare2 is installed
Installed - Info on how to do this can be found [here](https://github.com/radareorg/radare2).


## Experimental Features

`bin2ml` also has experimental features which are either still in active development or still being tested.

In order to activate these, the `--features` flag can be provided to `cargo` during the build process.

For example, if you wanted to activate the `inference` feature which provides support for loading TorchScript PyTorch models, `bin2ml` could be compiled using the following command:
```
cargo build --release --features inference
```