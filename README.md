# `bin2ml`

`bin2ml` is a command line tool to extract machine learning ready data from software binaries. It's ideal for researchers and hackers to easily extract data suitable for training machine learning approaches such as natural language processing (NLP) or Graph Neural Networks (GNN's) models using data derived from software binaries.

- Extract a range of different data from binaries such as Attributed Control Flow Graphs, Basic Block random walks and function instructions strings powered by [Radare2](https://github.com/radareorg/radare2).
- Multithreaded data processing throughout powered by [Rayon](https://github.com/rayon-rs/rayon).
- Save processed data in ready to go formats such as graphs saved as [NetworkX](https://networkx.org/) compatible JSON objects.
- Experimental support for creating machine learning embedded basic block CFG's using `tch-rs` and TorchScript traced models.

> `bin2ml` is under active development and is in an alpha state. Things will change as the tool is developed and built upon further.

## Pre-Requisites
- Radare2 Installed - Info on how to do this can be found [here](https://github.com/radareorg/radare2).

## Quickstart
```bash
git clone https://github.com/br0kej/bin2ml
cd bin2ml
cargo build --release
```
Alternatively, there is a Dockerfile provided too which provides a means of creating a container with a ready to go version of `bin2ml` in it

## Docs
`bin2ml` does come with some documentation (albeit incomplete) and has been developed using `mdbook`. The documentation can be locally served by installing the platform relevant version of `mdbook` from [here](https://github.com/rust-lang/mdBook/releases)
and then executing the commands below:
```bash
cd bin2ml/docs
mdbook serve
```
Alternatively, they can be viewed raw by going to the docs folder [here](docs/src/README.md)
## License

The `bin2ml` source and documentation are released under the MIT license.

## Citation

```bibtex
@misc{collyer2023bin2ml,
  author = {Josh Collyer},
  title = {bin2ml},
  year = {2023},
  publisher = {GitHub},
  journal = {GitHub repository},
  howpublished = {\url{https://github.com/br0kej/bin2ml/}},
}
```