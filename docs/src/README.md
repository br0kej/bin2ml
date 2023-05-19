# Introduction

*bin2ml* is a command line tool to extract machine learning ready data from software binaries. It's ideal for researchers and hackers to easily extract data suitable for training machine learning approaches such as natural language processing (NLP) or Graph Neural Networks (GNN's) models.

- Extract a range of different data from binaries such as Attributed Control Flow Graphs, Basic Block random walks and function instructions strings powered by [Radare2](https://github.com/radareorg/radare2).
- Multithreaded data processing throughout powered by [Rayon](https://github.com/rayon-rs/rayon).
- Save processed data in ready to go formats such as graphs saved as [NetworkX](https://networkx.org/) compatible JSON objects.
- Experimental support for creating machine learning embedded basic block CFG's using `tch-rs` and TorchScript traced models.

# Where next?

A great place to start is heading over to the [Installation Guide](./installation.md) or diving straight into [Introduction by Example](./intro_by_example.md).

# License

The `bin2ml` source and documentation are released under the MIT license.