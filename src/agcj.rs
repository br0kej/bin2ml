use crate::files::AGCJFile;
use crate::networkx::{CallGraphFuncNameNode, CallGraphFuncWithMetadata, NetworkxDiGraph};
use crate::utils::{check_or_create_dir, get_save_file_path};
use itertools::Itertools;
use petgraph::prelude::Graph;
use serde::{Deserialize, Serialize};
use std::fs::File;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AGCJFunctionCallGraphs {
    pub name: String,
    pub size: i64,
    pub imports: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AGCJParsedObjects {
    pub edge_property: String,
    pub edges: Vec<Vec<i32>>,
    pub node_holes: Vec<String>,
    pub nodes: Vec<String>,
}

impl AGCJFunctionCallGraphs {
    fn build_local_call_graph(&self) -> Graph<String, u32> {
        let mut graph = Graph::<String, u32>::new();
        let calling_func = graph.add_node(self.name.clone());
        if self.imports.is_some() {
            for ele in self.imports.as_ref().unwrap().iter() {
                let callee = graph.add_node(ele.clone());
                graph.update_edge(calling_func.clone(), callee, 0);
            }
            graph
        } else {
            graph
        }
    }

    fn graph_to_json_func_node(
        &self,
        binary_name: &str,
        output_path: &String,
        networkx_graph: NetworkxDiGraph<CallGraphFuncNameNode>,
        type_suffix: &str,
    ) {
        let full_output_path =
            get_save_file_path(binary_name, output_path, Some(type_suffix.to_string()));
        check_or_create_dir(&full_output_path);

        let mut function_name = self.name.clone();

        // This is a pretty dirty fix and may break things
        if function_name.chars().count() > 100 {
            function_name = self.name[..75].to_string();
        }

        let filename = format!(
            "{}/{}-{}.json",
            full_output_path, function_name, type_suffix
        );

        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &networkx_graph,
        )
        .expect("Unable to write JSON");
    }

    fn graph_to_json_func_metadata(
        &self,
        binary_name: &str,
        output_path: &String,
        networkx_graph: NetworkxDiGraph<CallGraphFuncWithMetadata>,
        type_suffix: &str,
    ) {
        let full_output_path =
            get_save_file_path(binary_name, output_path, Some(type_suffix.to_string()));
        check_or_create_dir(&full_output_path);

        let mut function_name = self.name.clone();

        // This is a pretty dirty fix and may break things
        if function_name.chars().count() > 100 {
            function_name = self.name[..75].to_string();
        }

        let filename = format!(
            "{}/{}-{}.json",
            full_output_path, function_name, type_suffix
        );

        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &networkx_graph,
        )
        .expect("Unable to write JSON");
    }

    fn get_callees_of_callees(&self, global_cg: &AGCJFile, graph: &mut Graph<String, u32>) {
        if self.imports.is_some() {
            for import in self.imports.as_ref().unwrap().iter() {
                let import_object: &Vec<&AGCJFunctionCallGraphs> = &global_cg
                    .function_call_graphs
                    .as_ref()
                    .unwrap()
                    .iter()
                    .filter(|cg| cg.name == *import)
                    .collect_vec();
                if !import_object.is_empty() {
                    for entry in import_object {
                        for ele in entry.imports.as_ref().unwrap().iter() {
                            let callee = graph.add_node(ele.clone());
                            let import_node_index =
                                graph.node_indices().find(|i| &graph[*i] == import).unwrap();
                            debug!("{:?} -> {:?}", import, ele);
                            graph.update_edge(import_node_index, callee, 0);
                        }
                    }
                }
            }
        }
    }

    fn get_target_func_callers(&self, global_cg: &AGCJFile, graph: &mut Graph<String, u32>) {
        let callers = &global_cg
            .function_call_graphs
            .as_ref()
            .unwrap()
            .iter()
            .filter(|cg| cg.imports.as_ref().unwrap().contains(&self.name))
            .collect_vec();

        for cg in callers.iter() {
            let caller = graph.add_node(cg.name.clone());
            let func_target_index = graph.node_indices().find(|i| graph[*i] == self.name);
            graph.update_edge(caller, func_target_index.unwrap(), 0);
        }
    }

    // Creates a petgraph object of a given function and all functions called as part of it's execution
    pub fn to_petgraph(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
        with_metadata: &bool,
    ) {
        let graph = self.build_local_call_graph();

        if *with_metadata {
            let networkx_graph =
                NetworkxDiGraph::from((graph, global_cg.function_metadata.as_ref().unwrap()));
            self.graph_to_json_func_metadata(binary_name, output_path, networkx_graph, "cg")
        } else {
            let networkx_graph = NetworkxDiGraph::from(graph);
            self.graph_to_json_func_node(binary_name, output_path, networkx_graph, "cg")
        };
    }

    // Creates a petgraph object of a given function, all of the functions called functions and
    // then their callees.
    pub fn one_hop_to_petgraph(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
        with_metadata: &bool,
    ) {
        let mut graph = self.build_local_call_graph();

        self.get_callees_of_callees(global_cg, &mut graph);

        if *with_metadata {
            let networkx_graph =
                NetworkxDiGraph::from((graph, global_cg.function_metadata.as_ref().unwrap()));
            self.graph_to_json_func_metadata(binary_name, output_path, networkx_graph, "1hop")
        } else {
            let networkx_graph = NetworkxDiGraph::from(graph);
            self.graph_to_json_func_node(binary_name, output_path, networkx_graph, "1hop")
        };
    }

    pub fn to_petgraph_with_callers(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
        with_metadata: &bool
    ) {
        let mut graph = self.build_local_call_graph();
        self.get_target_func_callers(global_cg, &mut graph);

        if *with_metadata {
            let networkx_graph =
                NetworkxDiGraph::from((graph, global_cg.function_metadata.as_ref().unwrap()));
            self.graph_to_json_func_metadata(binary_name, output_path, networkx_graph, "cg-callers")
        } else {
            let networkx_graph = NetworkxDiGraph::from(graph);
            self.graph_to_json_func_node(binary_name, output_path, networkx_graph, "cg-callers")
        };
    }

    pub fn one_hop_to_petgraph_with_callers(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
        with_metadata: &bool,
    ) {
        let mut graph = self.build_local_call_graph();

        self.get_target_func_callers(global_cg, &mut graph);
        self.get_callees_of_callees(global_cg, &mut graph);

        if *with_metadata {
            let networkx_graph =
                NetworkxDiGraph::from((graph, global_cg.function_metadata.as_ref().unwrap()));
            self.graph_to_json_func_metadata(binary_name, output_path, networkx_graph, "1hop-callers")
        } else {
            let networkx_graph = NetworkxDiGraph::from(graph);
            self.graph_to_json_func_node(binary_name, output_path, networkx_graph, "1hop-callers")
        };
    }

    pub fn print_callees(&self) {
        println!("{:?}", self.imports)
    }
}
