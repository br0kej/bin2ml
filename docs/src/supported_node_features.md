# Supported Node Features
## Graph Features

The `bin2ml generate graphs --feature-type` flag supports a number of different node features where features are extracted from the basic blocks and are typically simple counts.

| `feature-type` | Description | Paper | Features | Architecture |
| ----------- | ----------- |-----|---| --|
| `gemini` | Generates 7 out of 8 of the basic blocks features from the seminal Gemini Paper. | [Paper (arxiv)](https://arxiv.org/pdf/1708.06525.pdf)| <ul><li>Number of Call instructions</li><li>Number of Transfer Instructions</li><li>Number of Arithmetic Instructions</li><li>Number of Instructions</li><li>Numeric Consts</li><li>String Consts</li><li>Number of Offspring</li></ul> The final feature `betweeness` is calculated downstream natively in `networkx`| `x86/64` / `MIPS32/64` / `ARM32/64`|
| `dgis` | Generates the features used within DGIS paper. |[Paper (ieee)](https://ieeexplore.ieee.org/document/9892518) |<ul><li>Number of Stack operations</li><li>Number of arithmetic operations</li><li>Number of Logic Operations</li><li>Number of Compare operations</li><li>Number of Library Calls</li><li>Number of Unconditional Jumps</li><li>Number of Conditional Jumps</li><li>Number of Generic Instructions</li></ul> | `x86/64` / `MIPS32/64` / `ARM32/64`|
 `discovre`|Generates all 6 features used within the DisovRE paper | [Paper (ndss)](https://www.ndss-symposium.org/wp-content/uploads/2017/09/discovre-efficient-cross-architecture-identification-bugs-binary-code.pdf)| <ul><li>Number of Call instructions</li><li>Number of Transfer Instructions</li><li>Number of Arithmetic Instructions</li><li>Number of Instructions</li><li>Numeric Consts</li><li>String Consts</li></ul> | `x86/64` / `MIPS32/64` / `ARM32/64`|

