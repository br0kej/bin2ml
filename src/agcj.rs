use serde::{Deserialize, Serialize};
use petgraph::prelude::Graph;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AGCJFunctionCallGraphs {
    pub name: String,
    pub size: i64,
    pub imports: Vec<String>,
}

impl AGCJFunctionCallGraphs {
    pub fn to_petgraph(&self) {

        let mut graph = Graph::<String, u32>::new();

        let calling_func = graph.add_node(self.name.clone());
        for ele in self.imports.iter() {
            let callee = graph.add_node(ele.clone());
            graph.update_edge(calling_func, callee, 0);
        };
        println!("{:?}", graph);
    }

    pub fn return_callees(&self) /*-> Vec<String>*/ {
        println!("{:?}", self.imports)
    }
}
