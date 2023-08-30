use crate::files::AGCJFile;
use crate::networkx::NetworkxDiGraph;
use crate::utils::{check_or_create_dir,get_save_file_path};
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
    // Creates a petgraph object of a given function and all functions called as part of it's execution
    pub fn to_petgraph(&self, output_path: &String, binary_name: &String) {
        let mut graph = Graph::<String, u32>::new();

        let calling_func = graph.add_node(self.name.clone());
        for ele in self.imports.iter() {
            let callee = graph.add_node(ele.clone());
            graph.update_edge(calling_func, callee, 0);
        }
        let networkx_graph = NetworkxDiGraph::from(graph);
        let full_output_path = get_save_file_path(binary_name, output_path, None);
        check_or_create_dir(&full_output_path);
        let filename = format!("{}/{}-cg.json", full_output_path, self.name);
        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &networkx_graph,
        )
        .expect("Unable to write JSON");
    }

    // Creates a petgraph object of a given function, all of the functions called functions and
    // then their callees.
    pub fn one_hop_to_petgraph(&self, global_cg: &AGCJFile, output_path: &String, binary_name: &String) {
        let mut graph = Graph::<String, u32>::new();

        // Dealing with local call graph
        let calling_func = graph.add_node(self.name.clone());
        for ele in self.imports.iter() {
            let callee = graph.add_node(ele.clone());
            graph.update_edge(calling_func, callee, 0);
        }

        // Getting imports call graphs
        for import in self.imports.iter() {
            let import_object: &Option<&AGCJFunctionCallGraphs> = &global_cg
                .function_call_graphs
                .as_ref()
                .unwrap()
                .iter()
                .find(|cg| cg.name == *import);
            if import_object.is_some() {
                for ele in import_object.unwrap().imports.iter() {
                    let callee = graph.add_node(ele.clone());
                    let import_node_index =
                        graph.node_indices().find(|i| &graph[*i] == import).unwrap();
                    debug!("{} -> {}", import, ele);
                    graph.update_edge(import_node_index, callee, 0);
                }
            }
        }

        let networkx_graph = NetworkxDiGraph::from(graph);
        let full_output_path = get_save_file_path(binary_name, output_path, Some("1hop".to_string()));
        check_or_create_dir(&full_output_path);
        let filename = format!("{}/{}-1hopcg.json", full_output_path, self.name);

        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &networkx_graph,
        )
        .expect("Unable to write JSON");
    }

    pub fn print_callees(&self) {
        println!("{:?}", self.imports)
    }
}
