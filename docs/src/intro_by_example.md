# Intro by Example

This section introduces the core functionality of `bin2ml` in several short, self -ontained examples.

At it's core, `bin2ml` provides a means of automatically extracting data from binaries using `radare2` before then processing this data into ML ready data formats.

> This section is currently under development and will expand with examples as `bin2ml`'s functionality increases.

<!-- TOC -->
# Table of Contents
* [Example 1: From Graph Extraction to PyTorch Geometric `Data` Object](#example-1-from-graph-extraction-to-pytorch-geometric-data-object)
  * [Creating a test file](#creating-a-test-file)
  * [Extracting Intermediate Data](#extracting-intermediate-data)
  * [Generating `networkx` compatible Attributed Control Flow Graphs (ACFG's)](#generating-networkx-compatible-attributed-control-flow-graphs-acfgs)
  * [Loading `networkx` graph and converting to PyTorch Geometric `Data` Objects](#loading-networkx-graph-and-converting-to-pytorch-geometric-data-objects)
* [Example 2: `huggingface` Tokeniser Data Generation and Training](#example-2-huggingface-tokeniser-data-generation-and-training)
  * [Creating a test file](#creating-a-test-file-1)
  * [Extracting Intermediate Data](#extracting-intermediate-data-1)
  * [Creating a training corpus](#creating-a-training-corpus)
  * [Training a `hugginface` Tokeniser](#training-a-hugginface-tokeniser)
<!-- TOC -->

# Example 1: From Graph Extraction to PyTorch Geometric `Data` Object

The first stage is data extraction and this element of `bin2ml` builds on the shoulders of giants and uses `radare2`'s automation interface, `r2pipe`. This provides a flexible method of piping in `r2` commands and collecting the results. The primary supported command is `agfj` which essentially stands for *analyse graph functions and output in JSON*.

## Creating a test file

In order to take `bin2ml` out for a spin, we need a binary to process! The `bin2ml` repository comes with a simple test program which can be compiled as using the following command (assumes a C compiler is already installed):

```
cd /path/to/bin2mlrepo
gcc test-files/test_bin.c -o test-files/test_bin
```

## Extracting Intermediate Data
Once compiled, the file can be processed using
```
bin2ml extract --fpath test-files/test_bin --output-dir . --mode cfg
``` 
 Let's break this down.
1. `bin2ml extract` means we want to use the extraction functionality of `bin2ml`
2. `--fpath` determines what files or directories to processed. There is support for processing single files, single directories or nested directories.
3. `--output-dir` determines where you want to save the processed files.
4. `--mode` determines which extraction mode you want. `cfg` is `afgj`

This command will have created a `test_bin.json` containing the `agfj` output for each of the functions within the binary (A sample of this data can be found [here](agfj_output.md)). This output is very verbose and contains detailed information at an instruction and basic block level for each functions within the binary - Perfect for further processing!

## Generating `networkx` compatible Attributed Control Flow Graphs (ACFG's)

`bin2ml` makes it simple to create Attributed Control Flow Graphs (ACFG's) with a variety of different node features (Supported node features can be found [here](./supported_node_features.md)) which are then saved in `networkx` compatible JSON files.

The following command can be used to create Attributed Control Flow Graphs (ACFG's) with Gemini node features:

```
bin2ml generate graphs -p test_bin_cfg.json -o . -f gemini -d cfg
```

This will have created a `test_bin_cfg/` folder which contains three JSON files. Each of these JSON files is a `networkx` directed graph with node attributes. Try opening `test_bin-main.json` and it should look like the JSON you can see below.

```json
{
    "adjacency": [
        [
            {
                "id": 1,
                "weight": 1
            },
            {
                "id": 2,
                "weight": 2
            }
        ],
        [
            {
                "id": 3,
                "weight": 1
            }
        ],
        [
            {
                "id": 3,
                "weight": 1
            }
        ],
        [
            {
                "id": 4,
                "weight": 1
            },
            {
                "id": 5,
                "weight": 2
            }
        ],
        [
            {
                "id": 7,
                "weight": 1
            },
            {
                "id": 8,
                "weight": 2
            }
        ],
        [
            {
                "id": 6,
                "weight": 1
            }
        ],
        [],
        [
            {
                "id": 6,
                "weight": 1
            }
        ],
        [
            {
                "id": 6,
                "weight": 1
            }
        ]
    ],
    "directed": "True",
    "graph": [],
    "multigraph": false,
    "nodes": [
        {
            "id": 0,
            "num arith": 10.0,
            "num calls": 1.0,
            "num ins": 1.0,
            "num offspring": 2.0,
            "num transfer": 5.0,
            "numeric consts": 1.0,
            "string consts": 1.0
        },
        {
            "id": 1,
            "num arith": 4.0,
            "num calls": 1.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 2.0,
            "numeric consts": 0.0,
            "string consts": 1.0
        },
        {
            "id": 2,
            "num arith": 3.0,
            "num calls": 1.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 2.0,
            "numeric consts": 0.0,
            "string consts": 1.0
        },
        {
            "id": 3,
            "num arith": 5.0,
            "num calls": 0.0,
            "num ins": 1.0,
            "num offspring": 2.0,
            "num transfer": 2.0,
            "numeric consts": 0.0,
            "string consts": 0.0
        },
        {
            "id": 4,
            "num arith": 4.0,
            "num calls": 1.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 2.0,
            "numeric consts": 0.0,
            "string consts": 1.0
        },
        {
            "id": 5,
            "num arith": 2.0,
            "num calls": 0.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 0.0,
            "numeric consts": 1.0,
            "string consts": 0.0
        },
        {
            "id": 6,
            "num arith": 4.0,
            "num calls": 1.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 2.0,
            "numeric consts": 0.0,
            "string consts": 1.0
        },
        {
            "id": 7,
            "num arith": 3.0,
            "num calls": 1.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 2.0,
            "numeric consts": 0.0,
            "string consts": 1.0
        },
        {
            "id": 8,
            "num arith": 3.0,
            "num calls": 0.0,
            "num ins": 0.0,
            "num offspring": 2.0,
            "num transfer": 1.0,
            "numeric consts": 0.0,
            "string consts": 0.0
        }
    ]
}
```

## Loading `networkx` graph and converting to PyTorch Geometric `Data` Objects
This can then be loaded into `networkx` easily using the following commands:
```python
from networkx.readwrite import json_graph
fd = open("test_bin_cfg/test_bin-main.json")
json_data = json.load(fd)
G = json_graph.adjacency_graph(json_data)
```
To complete the Gemini feature set, we can also compute the betweenness and add that to the graph:
```python
bb = nx.betweenness_centrality(G)
nx.set_node_attributes(G, bb, "betweenness")
```
Now that we have a `networkx` graph we can easily convert this into a PyTorch Geometric `Data` object using the `from_networkx()` function ready for experimenting with graph neural networks (GNN's)!
```python
node_attr_names = ["num arith","num calls","num ins","num offspring","num transfer","numeric consts","string consts", "betweenness"]
pyg_data_tensor = from_networkx(G, group_node_attrs=node_attr_names)
```

# Example 2: `huggingface` Tokeniser Data Generation and Training

The first stage of this example is the same as `Example 1` - We must extract the raw data using `bin2ml`'s extract functionality. 

## Creating a test file

The `bin2ml` repository comes with a simple test program which can be compiled as using the following command (assumes a C compiler is already installed such as `gcc`):
```
cd /path/to/bin2mlrepo
gcc test-files/test_bin.c -o test-files/test_bin
```

## Extracting Intermediate Data
Once compiled, the file can be processed using
```
bin2ml extract --fpath test-files/test_bin --output-dir . --mode cfg
``` 

This command will have created a `test_bin.json` containing the `agfj` output for each of the functions within the binary (A sample of this data can be found [here](agfj_output.md)). This output is very verbose and contains detailed information at an instruction and basic block level for each functions within the binary - Perfect for further processing!

## Creating a training corpus

```bash
bin2ml generate nlp -p test_bin_cfg.json -i disasm -d . -o single 
```

This command will load the extracted data and create a text file containing each of the instructions from all functions with the JSON file.

## Training a `hugginface` Tokeniser

`bin2ml` takes advantage of the rust library that underpins huggingface tokenisers and uses it directly. We can now train a tokeniser using the data we just generated 
by executing the following command.

```bash
bin2ml generate tokeniser -d test_bin_cfg-dis-singles.txt -o test_bin_tokeniser.json --vocab-size 1000 -t byte-bpe
```

> The tokeniser created here is configured specifically for Masked Language Modelling tasks and is Byte-Level Byte Pair Encoding. Further configurations/support is likely to be added in the future.

