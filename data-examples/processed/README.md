# Processed Data Examples

This directory contains several examples of data generated using `bin2ml` dervied from a simple test binary.

## Graphs

| Path                            | Description                                                                                                                     |
|---------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `graphs/test_bin_cfg_dgis/`     | Attributed contol flow graphs (ACFG's) where the node features are the same as those described in Liu et al (2022) (1)          |
| `graphs/test_bin_cfg_discovre/` | Attributed contol flow graphs (ACFG's) where the node features are the same as those described in Eschweiler (2016 (2)          |
| `graphs/test_bin_cfg_gemini/`   | Attributed control flow graphs (ACFG's) where the node features are the same as those described in Xu et al (2017 (3)           |
| `graphs/test_bin_cg/`           | Networkx DiGraph JSON objects for a function's local call graph i.e the function and its calees                                 |
| `graphs/test_bin_cg-1hop/`      | Networkx DiGraph JSON objects for a function's one-hop neighbour hood i.e the function, its calees and the calees of the calees |

(1) Liu et al. (2022), ‘Dual-Granularity Interactive Semantic Learning Based Vulnerability Detection Approach for Cross-Platform Binary’.

(2) Eschweiler, S., Yakdan, K. and Gerhards-Padilla, E., 2016, February. discovRE: Efficient Cross-Architecture Identification of Bugs in Binary Code. In Ndss (Vol. 52, pp. 58-79).

(3) Xu, X., Liu, C., Feng, Q., Yin, H., Song, L. and Song, D., 2017, October. Neural network-based graph embedding for cross-platform binary code similarity detection. In Proceedings of the 2017 ACM SIGSAC conference on computer and communications security (pp. 363-376).

## Natural Language Processing (Text Data)
| Path                                | Description                                                                                                     |
|-------------------------------------|-----------------------------------------------------------------------------------------------------------------|
| `nlp/test_bin_cfg-dfs.json`         | Disassembly function strings - All instructions within a functon concatenated together into a long string.      |
| `nlp/test_bin_cfg-dis-singles.txt`  | Disassembly single instruction per line. Useful for pre-training instruction level language models.             |
| `nlp/test_bin_cfg-efs.json`         | Radare2 ESIL function strings - All ESIL instructions within a functon concatenated together into a long string | 
| `nlp/test_bin_cfg-esil-singles.txt` | Radare2 single instructions per line. Useful for pre-training instruction level language modelling.             | 

## Metadata
| Path                                        | Description                                                                                                                                                                                                                                       |
|---------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `metadata/test_bin_finfo-finfo-subset.json` | A subset of the high level information extract as part of the `finfo` `bin2ml extract` command. This includes summary info such as number of instructions in the function, number of edges, indegree and outdegree as well as function prototype. |

