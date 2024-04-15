use crate::afij::AFIJFeatureSubset;
use crate::agfj::TikNibFunc;
use crate::bb::{FeatureType, TikNibFeaturesBB};
use crate::combos::FinfoTiknib;
use enum_as_inner::EnumAsInner;
use petgraph::prelude::Graph;
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkxDiGraph<N> {
    pub adjacency: Vec<Vec<Adjacency>>,
    pub directed: String,
    pub graph: Vec<char>,
    pub multigraph: bool,
    pub nodes: Vec<N>,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Adjacency {
    pub id: usize,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumAsInner)]
pub enum NodeType {
    Gemini(GeminiNode),
    Dgis(DGISNode),
    Discovere(DiscovreNode),
    Tiknib(TiknibNode),
}

#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize, EnumAsInner)]
#[serde(untagged)]
pub enum CallGraphTypes {
    TikNib(NetworkxDiGraph<CallGraphTikNibFeatures>),
    CGMeta(NetworkxDiGraph<CallGraphFuncWithMetadata>),
    CGName(NetworkxDiGraph<CallGraphFuncNameNode>),
    TikNibFinfo(NetworkxDiGraph<CallGraphTikNibFinfoFeatures>),
}

#[derive(Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CallGraphNodeFeatureType {
    TikNib,
    CGMeta,
    CGName,
}

impl CallGraphNodeFeatureType {
    pub fn new(node_feature_type: &str) -> CallGraphNodeFeatureType {
        match node_feature_type {
            "cgmeta" => CallGraphNodeFeatureType::CGMeta,
            "cgname" => CallGraphNodeFeatureType::CGName,
            "tiknib" => CallGraphNodeFeatureType::TikNib,
            _ => unreachable!("Invalid node type"),
        }
    }
}

#[derive(Copy, Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TiknibNode {
    pub id: i64,
    pub features: TikNibFeaturesBB,
}
impl From<(i64, &Vec<f64>)> for TiknibNode {
    fn from(src: (i64, &Vec<f64>)) -> TiknibNode {
        TiknibNode {
            id: src.0,
            features: TikNibFeaturesBB::from(src.1),
        }
    }
}

#[derive(Default, Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiNode {
    pub id: i64,
    pub num_calls: f64,
    pub num_transfer: f64,
    pub num_arith: f64,
    pub num_ins: f64,
    pub numeric_consts: f64,
    pub string_consts: f64,
    pub num_offspring: f64,
}

impl From<(i64, &Vec<f64>)> for GeminiNode {
    fn from(src: (i64, &Vec<f64>)) -> GeminiNode {
        GeminiNode {
            id: src.0,
            num_calls: src.1[0],
            num_transfer: src.1[1],
            num_arith: src.1[2],
            num_ins: src.1[3],
            numeric_consts: src.1[4],
            string_consts: src.1[5],
            num_offspring: src.1[6],
        }
    }
}

#[derive(Default, Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DGISNode {
    pub id: i64,
    pub num_stack_ops: f64,
    pub num_arith_ops: f64,
    pub num_logic_ops: f64,
    pub num_cmp_ops: f64,
    pub num_lib_calls: f64,
    pub num_uncon_jumps: f64,
    pub num_con_jumps: f64,
    pub num_generic_ins: f64,
}

impl From<(i64, &Vec<f64>)> for DGISNode {
    fn from(src: (i64, &Vec<f64>)) -> DGISNode {
        DGISNode {
            id: src.0,
            num_stack_ops: src.1[0],
            num_arith_ops: src.1[1],
            num_logic_ops: src.1[2],
            num_cmp_ops: src.1[3],
            num_lib_calls: src.1[4],
            num_uncon_jumps: src.1[5],
            num_con_jumps: src.1[6],
            num_generic_ins: src.1[7],
        }
    }
}

#[derive(Default, Copy, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscovreNode {
    pub id: i64,
    pub num_calls: f64,
    pub num_transfer: f64,
    pub num_arith: f64,
    pub num_ins: f64,
    pub numeric_consts: f64,
    pub string_consts: f64,
}

impl From<(i64, &Vec<f64>)> for DiscovreNode {
    fn from(src: (i64, &Vec<f64>)) -> DiscovreNode {
        DiscovreNode {
            id: src.0,
            num_calls: src.1[0],
            num_transfer: src.1[1],
            num_arith: src.1[2],
            num_ins: src.1[3],
            numeric_consts: src.1[4],
            string_consts: src.1[5],
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphFuncNameNode {
    pub id: i64,
    pub func_name: String,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphFuncWithMetadata {
    pub id: i64,
    pub func_name: String,
    pub function_feature_subset: AFIJFeatureSubset,
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
            adjacency,
            directed: "True".to_string(),
            graph: vec![],
            multigraph: false,
            nodes,
        }
    }
}

impl From<(Graph<String, u32>, &Vec<AFIJFeatureSubset>)>
    for NetworkxDiGraph<CallGraphFuncWithMetadata>
{
    fn from(
        src_graph: (Graph<String, u32>, &Vec<AFIJFeatureSubset>),
    ) -> NetworkxDiGraph<CallGraphFuncWithMetadata> {
        let node_weights = src_graph.0.node_weights();
        let mut nodes: Vec<CallGraphFuncWithMetadata> = vec![];
        for (i, node_weight) in node_weights.enumerate() {
            let subset_object = src_graph.1.iter().find(|ele| &ele.name == node_weight);
            if let Some(subset_object) = subset_object {
                nodes.push(CallGraphFuncWithMetadata {
                    id: i as i64,
                    func_name: node_weight.to_owned(),
                    function_feature_subset: subset_object.clone(),
                })
            } else {
                nodes.push(CallGraphFuncWithMetadata {
                    id: i as i64,
                    func_name: node_weight.to_owned(),
                    function_feature_subset: Default::default(),
                })
            }
        }
        let mut adjacency: Vec<Vec<Adjacency>> = vec![];
        let node_indices = src_graph.0.node_indices();

        for node in node_indices {
            let mut node_adjacency_vec = vec![];
            let node_edges = src_graph.0.edges(node);
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
            adjacency,
            directed: "True".to_string(),
            graph: vec![],
            multigraph: false,
            nodes,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphTikNibFeatures {
    pub id: i64,
    pub func_name: String,
    pub features: TikNibFunc,
}

impl From<(Graph<String, u32>, &Vec<TikNibFunc>)> for NetworkxDiGraph<CallGraphTikNibFeatures> {
    fn from(
        src_graph: (Graph<String, u32>, &Vec<TikNibFunc>),
    ) -> NetworkxDiGraph<CallGraphTikNibFeatures> {
        let node_weights = src_graph.0.node_weights();
        let mut nodes: Vec<CallGraphTikNibFeatures> = vec![];
        for (i, node_weight) in node_weights.enumerate() {
            let subset_object = src_graph.1.iter().find(|ele| &ele.name == node_weight);
            if let Some(subset_object) = subset_object {
                nodes.push(CallGraphTikNibFeatures {
                    id: i as i64,
                    func_name: node_weight.to_owned(),
                    features: subset_object.clone(),
                })
            } else {
                nodes.push(CallGraphTikNibFeatures {
                    id: i as i64,
                    func_name: node_weight.to_owned(),
                    features: Default::default(),
                })
            }
        }
        let mut adjacency: Vec<Vec<Adjacency>> = vec![];
        let node_indices = src_graph.0.node_indices();

        for node in node_indices {
            let mut node_adjacency_vec = vec![];
            let node_edges = src_graph.0.edges(node);
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
            adjacency,
            directed: "True".to_string(),
            graph: vec![],
            multigraph: false,
            nodes,
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphTikNibFinfoFeatures {
    pub id: i64,
    pub func_name: String,
    pub features: FinfoTiknib,
}

impl From<(Graph<String, u32>, &Vec<FinfoTiknib>)>
    for NetworkxDiGraph<CallGraphTikNibFinfoFeatures>
{
    fn from(
        src_graph: (Graph<String, u32>, &Vec<FinfoTiknib>),
    ) -> NetworkxDiGraph<crate::networkx::CallGraphTikNibFinfoFeatures> {
        let node_weights = src_graph.0.node_weights();
        let mut nodes: Vec<crate::networkx::CallGraphTikNibFinfoFeatures> = vec![];
        for (i, node_weight) in node_weights.enumerate() {
            let subset_object = src_graph.1.iter().find(|ele| &ele.name == node_weight);
            if let Some(subset_object) = subset_object {
                nodes.push(crate::networkx::CallGraphTikNibFinfoFeatures {
                    id: i as i64,
                    func_name: node_weight.to_owned(),
                    features: subset_object.clone(),
                })
            } else {
                nodes.push(crate::networkx::CallGraphTikNibFinfoFeatures {
                    id: i as i64,
                    func_name: node_weight.to_owned(),
                    features: Default::default(),
                })
            }
        }
        let mut adjacency: Vec<Vec<Adjacency>> = vec![];
        let node_indices = src_graph.0.node_indices();

        for node in node_indices {
            let mut node_adjacency_vec = vec![];
            let node_edges = src_graph.0.edges(node);
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
            adjacency,
            directed: "True".to_string(),
            graph: vec![],
            multigraph: false,
            nodes,
        }
    }
}

impl From<(&Graph<String, u32>, &Vec<Vec<f64>>, FeatureType)> for NetworkxDiGraph<NodeType> {
    fn from(
        input: (&Graph<String, u32>, &Vec<Vec<f64>>, FeatureType),
    ) -> NetworkxDiGraph<NodeType> {
        let mut nodes: Vec<NodeType> = vec![];

        // Get nodes into the JSON thingie
        for (i, node_vector) in input.1.iter().enumerate() {
            let node: Option<NodeType> = match input.2 {
                FeatureType::Gemini => {
                    Some(NodeType::Gemini(GeminiNode::from((i as i64, node_vector))))
                }
                FeatureType::DGIS => Some(NodeType::Dgis(DGISNode::from((i as i64, node_vector)))),
                FeatureType::DiscovRE => Some(NodeType::Discovere(DiscovreNode::from((
                    i as i64,
                    node_vector,
                )))),
                FeatureType::Tiknib => {
                    Some(NodeType::Tiknib(TiknibNode::from((i as i64, node_vector))))
                }
                _ => None,
            };

            if let Some(node) = node {
                nodes.push(node);
            } else {
                error!("Failed to create node for input!")
            }
        }

        // Sort edges out
        let mut adjacency: Vec<Vec<Adjacency>> = vec![];
        let node_indices = input.0.node_indices();

        for node in node_indices {
            let mut node_adjacency_vec = vec![];
            let node_edges = input.0.edges(node);
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
            adjacency,
            directed: "True".to_string(),
            graph: vec![],
            multigraph: false,
            nodes,
        }
    }
}

impl From<NetworkxDiGraph<NodeType>> for NetworkxDiGraph<GeminiNode> {
    fn from(src: NetworkxDiGraph<NodeType>) -> NetworkxDiGraph<GeminiNode> {
        let inner_nodes_types: Vec<GeminiNode> = src
            .clone()
            .nodes
            .into_iter()
            .map(|el| *el.as_gemini().unwrap())
            .collect();

        NetworkxDiGraph {
            adjacency: src.adjacency,
            directed: src.directed,
            graph: vec![],
            multigraph: false,
            nodes: inner_nodes_types,
        }
    }
}

impl From<NetworkxDiGraph<NodeType>> for NetworkxDiGraph<DGISNode> {
    fn from(src: NetworkxDiGraph<NodeType>) -> NetworkxDiGraph<DGISNode> {
        let inner_nodes_types: Vec<DGISNode> = src
            .clone()
            .nodes
            .into_iter()
            .map(|el| *el.as_dgis().unwrap())
            .collect();

        NetworkxDiGraph {
            adjacency: src.adjacency,
            directed: src.directed,
            graph: vec![],
            multigraph: false,
            nodes: inner_nodes_types,
        }
    }
}

impl From<NetworkxDiGraph<NodeType>> for NetworkxDiGraph<DiscovreNode> {
    fn from(src: NetworkxDiGraph<NodeType>) -> NetworkxDiGraph<DiscovreNode> {
        let inner_nodes_types: Vec<DiscovreNode> = src
            .clone()
            .nodes
            .into_iter()
            .map(|el| *el.as_discovere().unwrap())
            .collect();

        NetworkxDiGraph {
            adjacency: src.adjacency,
            directed: src.directed,
            graph: vec![],
            multigraph: false,
            nodes: inner_nodes_types,
        }
    }
}

impl From<NetworkxDiGraph<NodeType>> for NetworkxDiGraph<TiknibNode> {
    fn from(src: NetworkxDiGraph<NodeType>) -> NetworkxDiGraph<TiknibNode> {
        let inner_nodes_types: Vec<TiknibNode> = src
            .clone()
            .nodes
            .into_iter()
            .map(|el| *el.as_tiknib().unwrap())
            .collect();

        NetworkxDiGraph {
            adjacency: src.adjacency,
            directed: src.directed,
            graph: vec![],
            multigraph: false,
            nodes: inner_nodes_types,
        }
    }
}
