use crate::bb::{ACFJBlock, FeatureType};
#[cfg(feature = "inference")]
use crate::inference::InferenceJob;
use crate::utils::get_save_file_path;
use petgraph::prelude::Graph;
use petgraph::visit::Dfs;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::json;
use serde_json::{Map, Number, Value};
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::path::Path;
#[cfg(feature = "inference")]
use std::process::exit;
#[cfg(feature = "inference")]
use std::sync::Arc;

#[derive(Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
struct EdgesList {
    edge_set: Vec<EdgePair>,
}

#[derive(Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EdgePair {
    src: u16,
    dest: u16,
    wt: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AGFJFunc {
    name: String,
    nargs: u64,
    ninstr: u64,
    nlocals: u64,
    offset: u64,
    size: Option<u64>,
    stack: u64,
    r#type: String,
    pub blocks: Vec<ACFJBlock>,
    addr_idx: Option<Vec<i64>>,
    pub edge_list: Option<Vec<(u32, u32, u32)>>,
    graph: Option<Graph<String, u32>>,
}

impl AGFJFunc {
    pub fn create_graph_struct_members(&mut self, min_blocks: &u16) {
        self.create_bb_edge_list(min_blocks);
        self.create_petgraph_from_edgelist();
    }

    pub fn get_esil_function_string(
        &self,
        min_blocks: &u16,
        reg_norm: bool,
    ) -> Option<(String, String)> {
        let mut esil_function = Vec::<String>::new();
        if self.blocks.len() >= (*min_blocks).into() && self.blocks[0].offset != 1 {
            for bb in &self.blocks {
                let esil: Vec<String> = bb.get_esil_bb(reg_norm);
                for ins in esil.iter() {
                    if !ins.is_empty() {
                        let split: Vec<String> = ins.split(',').map(|s| s.to_string()).collect();
                        let split_joined = split.join(" ");
                        esil_function.push(split_joined);
                    }
                }
            }
            let joined = esil_function.join(" ");
            Some((self.name.clone(), joined))
        } else {
            None
        }
    }

    pub fn get_disasm_function_string(
        &self,
        min_blocks: &u16,
        reg_norm: bool,
    ) -> Option<(String, String)> {
        let mut disasm_function = Vec::<String>::new();
        if self.blocks.len() >= (*min_blocks).into() && self.blocks[0].offset != 1 {
            for bb in &self.blocks {
                let disasm: Vec<String> = bb.get_disasm_bb(reg_norm);
                for ins in disasm.iter() {
                    if !ins.is_empty() {
                        let split: Vec<String> = ins.split(',').map(|s| s.to_string()).collect();
                        let split_joined = split.join(" ");
                        disasm_function.push(split_joined);
                    }
                }
            }
            let joined = disasm_function.join(" ");
            Some((self.name.clone(), joined))
        } else {
            None
        }
    }

    pub fn create_bb_edge_list(&mut self, min_blocks: &u16) {
        if self.blocks.len() > (*min_blocks).into() && self.blocks[0].offset != 1 {
            let mut addr_idxs = Vec::<i64>::new();

            let mut edge_list = Vec::<(u32, u32, u32)>::new();

            let min_offset: u64 = self.offset;
            let max_offset: u64 = self.offset + self.size.unwrap_or(0);

            for bb in &self.blocks {
                bb.get_block_edges(&mut addr_idxs, &mut edge_list, max_offset, min_offset)
            }
            self.addr_idx = Some(addr_idxs);
            self.edge_list = Some(edge_list);
        }
    }

    pub fn create_petgraph_from_edgelist(&mut self) {
        if self.edge_list.is_some() {
            let graph = Graph::<String, u32>::from_edges(self.edge_list.as_ref().unwrap());
            self.graph = Some(graph)
        }
    }

    pub fn get_function_instructions(
        &mut self,
        esil: bool,
        min_blocks: &u16,
        reg_norm: bool,
    ) -> Option<Vec<String>> {
        let mut function_instructions = Vec::<Vec<String>>::new();

        if self.blocks.len() >= (*min_blocks).into() {
            for bb in &self.blocks {
                if esil {
                    let bb_ins = bb.get_esil_bb(reg_norm);
                    function_instructions.push(bb_ins)
                } else {
                    let bb_ins = bb.get_ins();
                    function_instructions.push(bb_ins)
                }
            }
            let flat_vec = function_instructions.into_iter().flatten().collect();
            Some(flat_vec)
        } else {
            None
        }
    }
    // This function traverses the functions control flow graph and currently
    // calculates the number of instructions per node
    pub fn dfs_cfg(&self, max_hops: u8, esil: bool, reg_norm: bool) -> Vec<Vec<Vec<String>>> {
        let graph = self.graph.as_ref().unwrap();
        let mut disasm_walks = Vec::<Vec<Vec<String>>>::new();
        let mut hop_counter: u8 = 0;

        for start in graph.node_indices() {
            let mut single_disasm_walk = Vec::<Vec<String>>::new();
            let mut dfs = Dfs::new(&graph, start);
            while let Some(visited) = dfs.next(&graph) {
                if hop_counter >= max_hops {
                    hop_counter = 0;
                    break;
                } else {
                    let block_offset = self.addr_idx.as_ref().unwrap()[visited.index()];
                    let basic_block: Vec<&ACFJBlock> = self
                        .blocks
                        .iter()
                        .filter(|x| x.offset == block_offset)
                        .collect();

                    // IF MATCH FOUND, DO BLOCK PROCESSING STUFF HERE
                    if !basic_block.is_empty() {
                        if esil {
                            let bb_esil = basic_block.first().unwrap().get_esil_bb(reg_norm);
                            single_disasm_walk.push(bb_esil)
                        } else {
                            let bb_ins = basic_block.first().unwrap().get_ins();
                            single_disasm_walk.push(bb_ins)
                        }
                    }
                    hop_counter += 1;
                }
            }
            disasm_walks.push(single_disasm_walk);
        }
        disasm_walks
    }

    pub fn disasm_random_walks(
        &mut self,
        min_blocks: &u16,
        esil: bool,
        reg_norm: bool,
    ) -> Option<Vec<Vec<Vec<String>>>> {
        if self.blocks.len() > (*min_blocks).into() && self.blocks[0].offset != 1 {
            self.create_graph_struct_members(min_blocks);
            let disasm_walks = self.dfs_cfg(10, esil, reg_norm);
            Some(disasm_walks)
        } else {
            None
        }
    }

    fn check_or_create_dir(&self, full_output_path: &String) {
        if !Path::new(full_output_path).is_dir() {
            create_dir_all(full_output_path).expect("Unable to create directory!");
        }
    }

    #[cfg(feature = "inference")]
    pub fn generate_embedded_cfg(
        &self,
        path: &str,
        min_blocks: &u16,
        output_path: &String,
        feature_type: FeatureType,
        inference_job: &Option<Arc<InferenceJob>>,
    ) {
        println!("Processing {:?}", self.name);
        let full_output_path = get_save_file_path(path, output_path);
        self.check_or_create_dir(&full_output_path);

        // offset != 1 has been added to skip functions with invalid instructions
        if self.blocks.len() >= (*min_blocks).into() && self.blocks[0].offset != 1 {
            let mut addr_idxs = Vec::<i64>::new();

            let mut edge_list = Vec::<(u32, u32, u32)>::new();

            let mut feature_vecs = Vec::<_>::new();
            let mut feature_vec_of_vecs = Vec::<_>::new();
            let min_offset = self.offset;
            let max_offset = self.offset + self.size.unwrap_or(0);
            for bb in &self.blocks {
                bb.get_block_edges(&mut addr_idxs, &mut edge_list, max_offset, min_offset);
                if inference_job.is_some() {
                    let inference = inference_job.as_ref().unwrap().clone();
                    match feature_type {
                        FeatureType::ModelEmbedded => {
                            bb.generate_bb_embedding_esil(&mut feature_vecs, Arc::clone(&inference))
                        }
                        // Cant work out how to do this!
                        FeatureType::Encoded => {
                            bb.generate_bb_encoding_esil(
                                &mut feature_vec_of_vecs,
                                Arc::clone(&inference),
                            );
                        }
                        _ => unreachable!("This should be unreachable"),
                    }
                } else {
                    println!("Unable to generated embedded CFG as inference job is none!");
                    exit(1)
                }
            }

            if !edge_list.is_empty() {
                let mut graph = Graph::<std::string::String, u32>::from_edges(&edge_list);

                Self::str_to_hex_node_idxs(&mut graph, &mut addr_idxs);
                println!("{:?}", feature_type);
                let json_map: Option<Map<String, Value>> = if inference_job.is_some()
                    && feature_type == FeatureType::ModelEmbedded
                {
                    Self::petgraph_to_nx(&self.name, &graph, Some(feature_vecs), None, None)
                } else if feature_type == FeatureType::Encoded {
                    Self::petgraph_to_nx(&self.name, &graph, None, Some(feature_vec_of_vecs), None)
                } else {
                    Self::petgraph_to_nx(
                        &self.name,
                        &graph,
                        Some(feature_vecs),
                        None,
                        Some(feature_type),
                    )
                };

                let file_name = path.split('/').last().unwrap();
                let binary_name: Vec<_> = file_name.split(".j").collect();

                let fname_string = format!(
                    "{}/{}-{}.json",
                    &full_output_path, binary_name[0], self.name
                );
                serde_json::to_writer(
                    &File::create(fname_string).expect("Failed to create writer"),
                    &json_map,
                )
                .expect("Unable to write JSON");
            } else {
                println!("Function {} has no edges. Skipping...", self.name)
            }
        }
    }

    pub fn generate_attributed_cfg(
        &self,
        path: &str,
        min_blocks: &u16,
        output_path: &String,
        feature_type: FeatureType,
        architecture: &String,
    ) {
        let full_output_path = get_save_file_path(path, output_path);
        self.check_or_create_dir(&full_output_path);
        let file_name = path.split('/').last().unwrap();
        let binary_name: Vec<_> = file_name.split(".j").collect();
        let mut function_name = self.name.clone();

        // This is a pretty dirty fix and may break things
        if function_name.chars().count() > 100 {
            function_name = self.name[..75].to_string();
        }

        let fname_string = format!(
            "{}/{}-{}.json",
            &full_output_path, binary_name[0], function_name
        );

        if !Path::new(&fname_string).is_file() {
            // offset != 1 has been added to skip functions with invalid instructions
            if self.blocks.len() >= (*min_blocks).into() && self.blocks[0].offset != 1 {
                let mut addr_idxs = Vec::<i64>::new();
                let mut edge_list = Vec::<(u32, u32, u32)>::new();
                let mut feature_vecs = Vec::<_>::new();
                let feature_vec_of_vecs = Vec::<_>::new();

                let min_offset: u64 = self.offset;
                let max_offset: u64 = self.offset + self.size.unwrap_or(0);
                for bb in &self.blocks {
                    bb.get_block_edges(&mut addr_idxs, &mut edge_list, max_offset, min_offset);
                    bb.generate_bb_feature_vec(&mut feature_vecs, feature_type, architecture);
                }

                if !edge_list.is_empty() {
                    let mut graph = Graph::<std::string::String, u32>::from_edges(&edge_list);

                    Self::str_to_hex_node_idxs(&mut graph, &mut addr_idxs);
                    let json_map: Option<serde_json::Map<std::string::String, serde_json::Value>> =
                        if feature_type == FeatureType::Encoded {
                            Self::petgraph_to_nx(
                                &self.name,
                                &graph,
                                None,
                                Some(feature_vec_of_vecs),
                                None,
                            )
                        } else {
                            Self::petgraph_to_nx(
                                &self.name,
                                &graph,
                                Some(feature_vecs),
                                None,
                                Some(feature_type),
                            )
                        };
                    if json_map.is_some() {
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &json_map,
                        )
                        .expect("Unable to write JSON");
                    }
                } else {
                    println!("Function {} has no edges. Skipping...", self.name)
                }
            } else {
                println!(
                    "Function {} has already been processed. Skipping...",
                    self.name
                )
            }
        }
    }

    // This function transforms a petgraph graph
    // to a valid JSON object that can be loaded in Pythons
    // Networkx
    fn petgraph_to_nx(
        func_name: &String,
        graph: &Graph<String, u32>,
        feature_vecs: Option<Vec<Vec<f64>>>,
        feature_vec_of_vecs: Option<Vec<Vec<Vec<f64>>>>,
        feature_type: Option<FeatureType>,
    ) -> Option<serde_json::Map<std::string::String, serde_json::Value>> {
        // GRAPH TRANSFORMATION TO NETWORKX
        let mut json_graph = serde_json::to_value(graph).unwrap();

        // Add missing keys into JSON Object
        json_graph["directed"] = json!("True");
        json_graph["multigraph"] = json!(false);

        // Transform JSON Graph into a JSON Map to enable removal of keys we don't want anymore
        let mut json_map: Map<String, Value> =
            serde_json::from_value(json_graph).expect("failed to read file");
        json_map.remove("node_holes");
        json_map.remove("edge_property");

        // Fix the edge format
        let json_edges = json_map.get("edges").unwrap();
        let mut parsed_edges = serde_json::from_value::<EdgesList>(json_edges.to_owned()).unwrap();
        parsed_edges.edge_set.sort_by(|a, b| a.src.cmp(&b.src));

        let mut all_edge_list: Vec<Vec<HashMap<std::string::String, u16>>> = Vec::new();
        for _n in 0..graph.node_count() {
            let element: Vec<HashMap<std::string::String, u16>> = Vec::new();
            all_edge_list.push(element);
        }

        for (_i, edge_set) in parsed_edges.edge_set.iter().enumerate() {
            // Remove self loops
            if edge_set.dest != edge_set.src {
                all_edge_list[edge_set.src as usize].push(HashMap::new());
                let size = all_edge_list[edge_set.src as usize].len() - 1;
                all_edge_list[edge_set.src as usize][size].insert("id".to_string(), edge_set.dest);
                all_edge_list[edge_set.src as usize][size]
                    .insert("weight".to_string(), edge_set.wt);
            }
        }

        json_map.insert(
            "adjacency".to_string(),
            serde_json::to_value(all_edge_list).unwrap(),
        );
        json_map.remove("edges");

        // Fix Node Format
        let mut all_node_list: Vec<HashMap<std::string::String, Value>> = Vec::new();
        let n_nodes = graph.node_count();
        let mut equal_nodes_to_feature_vecs = true;

        if let Some(feature_vecs) = feature_vecs {
            let n_feature_vecs = feature_vecs.len();

            if n_nodes != n_feature_vecs {
                println!(
                    "{}: Number of Nodes to Number Feature Vecs is not equal!",
                    func_name
                );
                equal_nodes_to_feature_vecs = false;
            } else {
                // PROBLEM AREA!
                let feature_map: Option<Vec<&str>> =
                    feature_type.map(|feature_type| feature_type.get_feature_map());

                #[allow(clippy::needless_range_loop)]
                for n in 0..n_nodes {
                    let mut node_ele: HashMap<std::string::String, Value> = HashMap::new();
                    node_ele.insert("id".to_string(), Value::Number(Number::from(n)));

                    // Generate vectors as normal!
                    if feature_type.is_some() {
                        for (i, val) in feature_map.as_ref().unwrap().iter().enumerate() {
                            node_ele.insert(val.to_string(), Value::from(feature_vecs[n][i]));
                        }
                        all_node_list.push(node_ele);
                    } else {
                        node_ele
                            .insert("features".to_string(), Value::from(feature_vecs[n].clone()));
                        all_node_list.push(node_ele);
                    }
                }
            }
        } else if let Some(feature_vecs_of_vecs) = feature_vec_of_vecs {
            let n_feature_vecs = feature_vecs_of_vecs.len();
            assert_eq!(
                n_nodes, n_feature_vecs,
                "\nFailed for function: {} had {} nodes and {} feature vectors",
                func_name, n_nodes, n_feature_vecs
            );
            #[allow(clippy::needless_range_loop)]
            for n in 0..n_nodes {
                let mut node_ele: HashMap<std::string::String, Value> = HashMap::new();
                node_ele.insert("id".to_string(), Value::Number(Number::from(n)));

                node_ele.insert(
                    "features".to_string(),
                    Value::from(feature_vecs_of_vecs[n].clone()),
                );
                all_node_list.push(node_ele);
            }
        } else {
            for n in 0..n_nodes {
                let mut node_ele: HashMap<std::string::String, Value> = HashMap::new();
                node_ele.insert("id".to_string(), Value::Number(Number::from(n)));
                all_node_list.push(node_ele);
            }
        }

        if equal_nodes_to_feature_vecs {
            json_map.remove("nodes");
            json_map.insert(
                "nodes".to_string(),
                serde_json::to_value(all_node_list).unwrap(),
            );

            // Adding missing expected key 'graph'
            let empty_vec = Vec::<i8>::new();
            json_map.insert(
                "graph".to_string(),
                serde_json::to_value(empty_vec).unwrap(),
            );
            Some(json_map)
        } else {
            None
        }
    }

    // Convert string memory address to hex / string
    fn str_to_hex_node_idxs(graph: &mut Graph<String, u32>, addr_idxs: &mut [i64]) {
        for idx in graph.node_indices() {
            let i_idx = idx.index();
            let hex = addr_idxs[i_idx];
            graph[idx] = format!("{hex:#x} / {hex}");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bb::FeatureType;

    use crate::AGFJFile;

    #[test]
    fn test_example_in_graph_rs() {
        assert_eq!(1, 1);
    }

    #[test]
    fn file_struct_creation() {
        let file_path = "../sample-tool-outputs/r2/example_agfj@@F_output.json".to_string();
        let file = AGFJFile {
            functions: None,
            filename: file_path.to_owned(),
            output_path: "output.json".to_string(),
            min_blocks: 5,
            feature_type: Some(crate::bb::FeatureType::Gemini),
            architecture: None,
        };

        assert!(file.functions.is_none());
        assert_eq!(
            file.filename,
            "../sample-tool-outputs/r2/example_agfj@@F_output.json".to_string()
        );
        assert_eq!(file.output_path, "output.json".to_string());
        assert_eq!(file.min_blocks, 5);
        assert_eq!(file.feature_type, Some(FeatureType::Gemini));
    }

    #[test]
    fn test_file_load_and_desearlize() {
        let file_path = "test-files/r2-output-samples/example_agfj@@F_output.json".to_string();
        let mut file = AGFJFile {
            functions: None,
            filename: file_path.to_owned(),
            output_path: "output.json".to_string(),
            min_blocks: 5,
            feature_type: Some(crate::bb::FeatureType::Gemini),
            architecture: None,
        };

        let ret = file.load_and_deserialize();

        // Check returned is an OK result
        assert!(ret.is_ok());

        // Check to see if the length is correct - Expect 40 functions
        assert_eq!(file.functions.as_ref().unwrap().len(), 40);
        // Check to see if the first function has length 1
        assert_eq!(file.functions.as_ref().unwrap()[0].len(), 1);
        // Check to attributes of first function
        assert_eq!(file.functions.as_ref().unwrap()[0][0].name, "main");
        assert_eq!(file.functions.as_ref().unwrap()[0][0].offset, 4294980912);
        assert_eq!(file.functions.as_ref().unwrap()[0][0].ninstr, 78);
        assert_eq!(file.functions.as_ref().unwrap()[0][0].nargs, 2);
        assert_eq!(file.functions.as_ref().unwrap()[0][0].nlocals, 0);
        assert_eq!(file.functions.as_ref().unwrap()[0][0].size, Some(334));
        assert_eq!(file.functions.as_ref().unwrap()[0][0].stack, 56);
        assert!(!file.functions.as_ref().unwrap()[0][0].blocks.is_empty());

        // Check first function has correct number of blocks - Expect 18
        assert_eq!(file.functions.as_ref().unwrap()[0][0].blocks.len(), 18);

        // Check the first block in the first function has the expected features
        assert_eq!(
            file.functions.as_ref().unwrap()[0][0].blocks[0].offset,
            4294980912
        );
        assert_eq!(
            file.functions.as_ref().unwrap()[0][0].blocks[0].jump,
            4294980968
        );
        assert!(!file.functions.as_ref().unwrap()[0][0].blocks[0]
            .ops
            .is_empty());
        assert_eq!(file.functions.as_ref().unwrap()[0][0].blocks[0].fail, -1);

        assert!(file.functions.as_ref().unwrap()[0][0].blocks[0]
            .switchop
            .is_none());

        // Check the second block in the first function has the expected features
        assert_eq!(
            file.functions.as_ref().unwrap()[0][0].blocks[1].offset,
            4294980968
        );
        assert_eq!(
            file.functions.as_ref().unwrap()[0][0].blocks[1].jump,
            4294981019
        );
        assert!(!file.functions.as_ref().unwrap()[0][0].blocks[1]
            .ops
            .is_empty());
        assert_eq!(
            file.functions.as_ref().unwrap()[0][0].blocks[1].fail,
            4294980986
        );
        assert!(file.functions.as_ref().unwrap()[0][0].blocks[1]
            .switchop
            .is_none());

        // Check switchops handled correctly when present
        assert!(file.functions.as_ref().unwrap()[0][0].blocks[3]
            .switchop
            .is_some());
    }

    #[test]
    fn test_func_edge_list_generation() {
        let file_path = "test-files/r2-output-samples/test_bin_agfj.json".to_string();
        let mut file = AGFJFile {
            functions: None,
            filename: file_path.to_owned(),
            output_path: "output.json".to_string(),
            min_blocks: 5,
            feature_type: Some(crate::bb::FeatureType::Gemini),
            architecture: None,
        };

        file.load_and_deserialize().unwrap();
        let target_func = &mut file.functions.unwrap()[9][0];

        // Check we have targetted the correct function
        assert_eq!(target_func.name, "main");

        // Check edge and address lists are blank before processing
        assert!(target_func.edge_list.is_none());
        assert!(target_func.addr_idx.is_none());
        target_func.create_bb_edge_list(&1);

        // Check edge list is now not blank before processing
        assert!(target_func.edge_list.is_some());
        // Check edge list is correct length
        assert_eq!(target_func.edge_list.as_ref().unwrap().len(), 11);

        // Check edge list output is the correct format
        let expected_edge_list = Some(vec![
            (0, 1, 1),
            (0, 2, 2),
            (2, 3, 1),
            (1, 3, 1),
            (3, 4, 1),
            (3, 5, 2),
            (5, 6, 1),
            (4, 7, 1),
            (4, 8, 2),
            (8, 6, 1),
            (7, 6, 1),
        ]);
        assert_eq!(target_func.edge_list, expected_edge_list)
    }
}
