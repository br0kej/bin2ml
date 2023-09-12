use crate::files::AGCJFile;
use crate::networkx::{CallGraphFuncNameNode, NetworkxDiGraph};
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
    pub imports: Vec<String>,
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
        for ele in self.imports.iter() {
            let callee = graph.add_node(ele.clone());
            graph.update_edge(calling_func, callee, 0);
        }
        graph
    }

    fn graph_to_json(
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

        let filename = format!("{}/{}-{}.json", full_output_path, self.name, type_suffix);

        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &networkx_graph,
        )
        .expect("Unable to write JSON");
    }

    fn get_callees_of_callees(&self, global_cg: &AGCJFile, graph: &mut Graph<String, u32>) {
        for import in self.imports.iter() {
            let import_object: &Vec<&AGCJFunctionCallGraphs> = &global_cg
                .function_call_graphs
                .as_ref()
                .unwrap()
                .iter()
                .filter(|cg| cg.name == *import)
                .collect_vec();
            if !import_object.is_empty() {
                for entry in import_object {
                    for ele in entry.imports.iter() {
                        let callee = graph.add_node(ele.clone());
                        let import_node_index =
                            graph.node_indices().find(|i| &graph[*i] == import).unwrap();
                        debug!("{} -> {}", import, ele);
                        graph.update_edge(import_node_index, callee, 0);
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
            .filter(|cg| cg.imports.contains(&self.name))
            .collect_vec();

        for cg in callers.iter() {
            let caller = graph.add_node(cg.name.clone());
            let func_target_index = graph.node_indices().find(|i| &graph[*i] == &self.name);
            graph.update_edge(caller, func_target_index.unwrap(), 0);
        }
    }

    // Creates a petgraph object of a given function and all functions called as part of it's execution
    pub fn to_petgraph(&self, output_path: &String, binary_name: &str) {
        let graph = self.build_local_call_graph();
        let networkx_graph = NetworkxDiGraph::from(graph);
        self.graph_to_json(binary_name, output_path, networkx_graph, "cg")
    }

    // Creates a petgraph object of a given function, all of the functions called functions and
    // then their callees.
    pub fn one_hop_to_petgraph(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
    ) {
        let mut graph = self.build_local_call_graph();

        self.get_callees_of_callees(global_cg, &mut graph);

        let networkx_graph = NetworkxDiGraph::from(graph);
        self.graph_to_json(binary_name, output_path, networkx_graph, "1hop")
    }

    pub fn to_petgraph_with_callers(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
    ) {
        let mut graph = self.build_local_call_graph();
        self.get_target_func_callers(global_cg, &mut graph);
        let networkx_graph = NetworkxDiGraph::from(graph);
        self.graph_to_json(binary_name, output_path, networkx_graph, "cg-callers")
    }

    pub fn one_hop_to_petgraph_with_callers(
        &self,
        global_cg: &AGCJFile,
        output_path: &String,
        binary_name: &str,
    ) {
        let mut graph = self.build_local_call_graph();

        self.get_target_func_callers(global_cg, &mut graph);
        self.get_callees_of_callees(global_cg, &mut graph);

        let networkx_graph = NetworkxDiGraph::from(graph);
        self.graph_to_json(binary_name, output_path, networkx_graph, "1hop-callers")
    }

    pub fn print_callees(&self) {
        println!("{:?}", self.imports)
    }
}
