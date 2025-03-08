# Binary Data Extraction
## Core Functionality
`bin2ml` generates ML-ready data from JSON files, which contain raw data about software binaries, extracted with Radare2. In the example below we produce one of such JSON files from a binary file called `target_bin`: 

```bash
bin2ml extract --fpath path/to/target_bin --output-dir path/to/output_dir --modes cfg
``` 

The argument `--fpath` can also accepd a directory path to recursively extract data from all binaries within that folder. As a result, `bin2ml` will save the output of `r2pipe` to `path/to/output_dir/target_bin_cfg.json`. [^extractsource]

[^extractsource]: For more information refer to the implementation `FileToBeProcessed` in extract.rs.

## Multiple Modes
Previously, we demonstrated how to extract output from a single Radare2 command (`agfj @@f`). You can also execute multiple extraction modes simultaneously, significantly speeding up the analysis process when multiple types of features are needed:
```bash
bin2ml extract --fpath path/to/target_bin --output-dir path/to/output_dir --modes cfg decomp strings
```

## Supported Extraction Modes

The following table summarises each extraction mode supported by `bin2ml extract`, including their respective Radare2 commands, output types, and recommended usage with the `bin2ml generate` command:

| Mode             | Radare2 Command      | Output Type       | Usage with `bin2ml generate`                                  |
|------------------|----------------------|------------------|-------------------------------------------------------------|
| **finfo**        | `finfo`            | JSON (function metadata) | Call graph generation with `--with-features`; Node features: `--metadata-type finfo`, `finfo-tiknib` |
| **reg**          | `aeafj`               | JSON (register usage per function) | N/A |
| **cfg**          | `agfj`                | JSON (CFG structure, basic blocks, instructions) | Graphs (`--data-type cfg`) with features: `gemini`, `discovre`, `dgis`, `tiknib`, `disasm`, `esil`, `pcode`, `pseudo`, `embed`, `encode` (planned). NLP sequences: `disasm`, `esil`, `pcode` |
| **func-xrefs**   | `axffj` | JSON (function call relationships) | Call graph generation (`cg`, `onehopcg`, etc.). Node features: `cgmeta`, `cgname`, `tiknib` |
| **cg**           | `agCj`                | JSON (call graph structure) | Call graph generation (`cg`, `onehopcg`, etc.). Node features: `cgmeta`, `cgname`, `tiknib` |
| **decomp**       | `pdgj` | JSON (decompiled functions) | N/A |
| **pcode-func**   | `pdgsd` | JSON (function-level P-Code) | NLP generation with `--instruction-type pcode`, set `--pcode-file-format pcode-func`. |
| **pcode-bb**     | `pdgsd` | JSON (basic-block-level P-Code) | NLP generation with `--instruction-type pcode`, set `--pcode-file-format pcode-bb`. CFG generation with `--data-type cfg` and `--feature-type pcode` |
| **localvar-xrefs** | `axvj` | JSON (local variable usage) | N/A |
| **strings**      | `izj`                 | JSON (strings in binary) | N/A |
| **bytes**        | N/A | Binary files (raw bytes per function) | N/A |

> **Note:** Some experimental features may require specific build flags, such as `--features inference` for embedding generation.

