use petgraph::prelude::Graph;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkxDiGraph<N> {
    pub adjacency: Vec<Vec<Adjacency>>,
    pub directed: String,
    pub graph: Vec<char>,
    pub multigraph: bool,
    pub nodes: Vec<N>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Adjacency {
    pub id: usize,
    pub weight: u32,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiNode {
    pub id: i64,
    #[serde(rename = "num arith")]
    pub num_arith: f64,
    #[serde(rename = "num calls")]
    pub num_calls: f64,
    #[serde(rename = "num ins")]
    pub num_ins: f64,
    #[serde(rename = "num offspring")]
    pub num_offspring: f64,
    #[serde(rename = "num transfer")]
    pub num_transfer: f64,
    #[serde(rename = "numeric consts")]
    pub numeric_consts: f64,
    #[serde(rename = "string consts")]
    pub string_consts: f64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphFuncNameNode {
    pub id: i64,
    pub func_name: String,
}

impl From<Graph<String, u32>> for NetworkxDiGraph<CallGraphFuncNameNode> {
    fn from(src_graph: Graph<String, u32>) -> NetworkxDiGraph<CallGraphFuncNameNode> {
        let node_weights = src_graph.node_weights();
        let mut nodes: Vec<CallGraphFuncNameNode> = vec![];
        for (i, node_weight) in node_weights.enumerate() {
            nodes.push(CallGraphFuncNameNode {
                id: i as i64,
                func_name: node_weight.to_owned(),
            })
        }
        let mut adjacency: Vec<Vec<Adjacency>> = vec![];
        let node_indices = src_graph.node_indices();

        for node in node_indices {
            let mut node_adjacency_vec = vec![];
            let node_edges = src_graph.edges(node);
            for edge in node_edges {
                let edge_entry = Adjacency {
                    id: edge.target().index(),
                    weight: edge.weight().to_owned(),
                };
                node_adjacency_vec.push(edge_entry)
            }
            adjacency.push(node_adjacency_vec)
        }

        NetworkxDiGraph {
            adjacency: adjacency,
            directed: "True".to_string(),
            graph: vec![],
            multigraph: false,
            nodes: nodes,
        }
    }
}
