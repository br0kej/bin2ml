# Experimental Features

| Feature Name | Purpose | Flag to activate |
|---------------|--------|------------------|
|`inference`| The purpose of the inference feature is to support the embedding of basic blocks using a pre-trained model. This uses the `tch-rs` create which is a rust front end for the C++ PyTorch API. This currently only supports CPU based inference and requires the model to output a single tensor (for example, if using HuggingFace transformers, the output head has to be changed)| `--features inference`
| `goblin` | The purpose of the goblin feature is to support getting info from an input binary such as architecture, section sizes etc. | `--features goblin`| 