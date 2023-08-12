use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AGCJFunctionCallGraphs {
    pub name: String,
    pub size: i64,
    pub imports: Vec<String>,
}

impl AGCJFunctionCallGraphs {

    fn to_petgraph() {
        todo!()
    }

    fn to_petgraph_one_hop() {
        todo!()
    }
}