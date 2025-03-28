use crate::bb::{ACFJBlock, FeatureType, TikNibFeaturesBB};
#[cfg(feature = "inference")]
use crate::inference::InferenceJob;
use crate::networkx::{
    DGISNode, DisasmNode, DiscovreNode, EsilNode, GeminiNode, NetworkxDiGraph, NodeType,
    PseudoNode, TiknibNode,
};
use crate::utils::{average, check_or_create_dir, get_save_file_path};
use enum_as_inner::EnumAsInner;
use itertools::Itertools;
use ordered_float::OrderedFloat;
use petgraph::prelude::Graph;
use petgraph::visit::Dfs;
use serde::{Deserialize, Serialize};
use serde_json;
#[cfg(feature = "inference")]
use serde_json::{Map, Value};
use std::fs::File;
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
    pub name: String,
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

#[derive(EnumAsInner, Serialize, Deserialize, Debug)]
pub enum StringOrF64 {
    String(Vec<Vec<String>>),
    F64(Vec<Vec<f64>>),
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
        if self.blocks.len() >= <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
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
        if self.blocks.len() >= <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
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

    pub fn get_psuedo_function_string(
        &self,
        min_blocks: &u16,
        reg_norm: bool,
    ) -> Option<(String, String)> {
        let mut psuedo_function = Vec::<String>::new();
        if self.blocks.len() >= <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
            for bb in &self.blocks {
                let psuedo: Vec<String> = bb.get_psuedo_bb(reg_norm);
                for ins in psuedo.iter() {
                    if !ins.is_empty() {
                        let split: Vec<String> = ins.split(',').map(|s| s.to_string()).collect();
                        let split_joined = split.join(" ");
                        psuedo_function.push(split_joined);
                    }
                }
            }
            let joined = psuedo_function.join(" ");
            Some((self.name.clone(), joined))
        } else {
            None
        }
    }
    pub fn create_bb_edge_list(&mut self, min_blocks: &u16) {
        if self.blocks.len() > <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
            let bb_start_addrs: Vec<i64> = self.blocks.iter().map(|x| x.offset).collect::<Vec<_>>();
            let mut edge_list = Vec::<(u32, u32, u32)>::new();

            for bb in &self.blocks {
                bb.get_block_edges(&bb_start_addrs, &mut edge_list)
            }
            self.addr_idx = Some(bb_start_addrs);
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

        if self.blocks.len() >= <u16 as Into<usize>>::into(*min_blocks) {
            for bb in &self.blocks {
                if esil {
                    let bb_ins = bb.get_esil_bb(reg_norm);
                    function_instructions.push(bb_ins)
                } else {
                    let bb_ins = bb.get_ins(reg_norm);
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
    pub fn dfs_cfg(
        &self,
        max_hops: u8,
        esil: bool,
        reg_norm: bool,
        pairs: bool,
    ) -> Vec<Vec<String>> {
        let graph = self.graph.as_ref().unwrap();
        let mut disasm_walks = Vec::<Vec<String>>::new();
        let mut hop_counter: u8 = 0;

        for start in graph.node_indices() {
            let mut single_disasm_walk = Vec::new();
            let mut dfs = Dfs::new(&graph, start);
            while let Some(visited) = dfs.next(&graph) {
                if hop_counter >= max_hops {
                    hop_counter = 0;
                    break;
                }
                let block_offset = self.addr_idx.as_ref().unwrap()[visited.index()];
                let basic_block: Vec<&ACFJBlock> = self
                    .blocks
                    .iter()
                    .filter(|x| x.offset == block_offset)
                    .collect();

                if !basic_block.is_empty() {
                    if esil {
                        let bb_esil = basic_block.first().unwrap().get_esil_bb(reg_norm);
                        single_disasm_walk.push(bb_esil)
                    } else {
                        let bb_ins = basic_block.first().unwrap().get_ins(reg_norm);
                        single_disasm_walk.push(bb_ins)
                    }
                }
                hop_counter += 1;
            }
            if pairs {
                let single_disasm_walk: Vec<String> =
                    single_disasm_walk.into_iter().flatten().collect();
                let mut pairs_disasm_walk = Vec::<String>::new();

                let len_of_walk = &single_disasm_walk.len();
                for (i, mut _instruction) in single_disasm_walk.iter().enumerate() {
                    if (i + 1) < *len_of_walk {
                        let pair = format!(
                            "{}      {}",
                            single_disasm_walk[i].clone(),
                            single_disasm_walk[i + 1].clone()
                        )
                        .to_string();

                        pairs_disasm_walk.push(pair);
                    };
                }
                disasm_walks.push(pairs_disasm_walk)
            } else {
                // This is really janky and likely bad for performance. Something to revisit!
                let single_disasm_walk: Vec<&String> =
                    single_disasm_walk.iter().flatten().collect();
                let single_disasm_walk = single_disasm_walk
                    .iter()
                    .map(|x| x.to_string())
                    .collect_vec();
                disasm_walks.push(single_disasm_walk);
            }
        }
        disasm_walks
    }

    pub fn disasm_random_walks(
        &mut self,
        min_blocks: &u16,
        esil: bool,
        reg_norm: bool,
        pairs: bool,
    ) -> Option<Vec<Vec<String>>> {
        if self.blocks.len() > <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
            self.create_graph_struct_members(min_blocks);
            let disasm_walks = self.dfs_cfg(10, esil, reg_norm, pairs);
            Some(disasm_walks)
        } else {
            None
        }
    }

    #[cfg(feature = "inference")]
    pub fn generate_embedded_cfg(
        &self,
        path: &PathBuf,
        min_blocks: &u16,
        output_path: &PathBuf,
        feature_type: FeatureType,
        inference_job: &Option<Arc<InferenceJob>>,
    ) {
        /*
        This function needs some serious sorting out.

        - Need to get GPU toggle-able
        - Need to use new CFG edge builder
        - General refactor
         */
        info!("Processing {:?}", self.name);
        let full_output_path =
            get_save_file_path(path, output_path, Some(".json".to_string()), None, None);
        check_or_create_dir(&full_output_path);

        // offset != 1 has been added to skip functions with invalid instructions
        if self.blocks.len() >= <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
            let bb_start_addrs: Vec<i64> = self.blocks.iter().map(|x| x.offset).collect::<Vec<_>>();
            let mut edge_list = Vec::<(u32, u32, u32)>::new();

            let mut feature_vecs = Vec::<_>::new();
            let mut feature_vec_of_vecs = Vec::<_>::new();

            for bb in &self.blocks {
                bb.get_block_edges(&bb_start_addrs, &mut edge_list);
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
                    info!("Unable to generated embedded CFG as inference job is none!");
                    exit(1)
                }
            }

            if !edge_list.is_empty() {
                let mut graph = Graph::<std::string::String, u32>::from_edges(&edge_list);

                Self::str_to_hex_node_idxs(&mut graph, &mut addr_idxs);
                info!("Feature Type: {:?}", feature_type);
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

                let file_name = path.file_name().unwrap();
                let binary_name: Vec<_> = file_name.split(".j").collect();

                let fname_string = format!(
                    "{:?}/{:?}-{}.json",
                    &full_output_path, binary_name[0], self.name
                );
                serde_json::to_writer(
                    &File::create(fname_string).expect("Failed to create writer"),
                    &json_map,
                )
                .expect("Unable to write JSON");
            } else {
                info!("Function {} has no edges. Skipping...", self.name)
            }
        }
    }

    pub fn generate_attributed_cfg(
        &self,
        path: &Path,
        min_blocks: &u16,
        output_path: &Path,
        feature_type: FeatureType,
        architecture: &String,
    ) {
        let full_output_path = get_save_file_path(
            path,
            output_path,
            None,
            Some(feature_type.to_string()),
            None,
        );
        check_or_create_dir(&full_output_path);
        let file_name = path.file_name().unwrap();
        let binding = file_name.to_string_lossy().to_string();

        let binary_name: Vec<_> = binding.split(".j").collect();

        let function_name = if self.name.chars().count() > 100 {
            &self.name[..75]
        } else {
            &self.name
        };

        let fname_string = format!(
            "{}/{}-{}.json",
            &full_output_path.to_string_lossy(),
            binary_name[0],
            function_name
        );

        if !Path::new(&fname_string).is_file() {
            // offset != 1 has been added to skip functions with invalid instructions
            if self.blocks.len() >= <u16 as Into<usize>>::into(*min_blocks) && self.blocks[0].offset != 1 {
                let mut edge_list = Vec::<(u32, u32, u32)>::new();

                let mut feature_vecs: StringOrF64 = match feature_type {
                    FeatureType::Tiknib
                    | FeatureType::Gemini
                    | FeatureType::DiscovRE
                    | FeatureType::DGIS => StringOrF64::F64(Vec::new()),
                    FeatureType::Esil
                    | FeatureType::Disasm
                    | FeatureType::Pseudo
                    | FeatureType::Pcode => StringOrF64::String(Vec::new()),
                    FeatureType::ModelEmbedded | FeatureType::Encoded | FeatureType::Invalid => {
                        info!("Invalid Feature Type. Skipping..");
                        return;
                    }
                };

                let bb_start_addrs: Vec<i64> =
                    self.blocks.iter().map(|x| x.offset).collect::<Vec<_>>();

                match feature_type {
                    FeatureType::Tiknib
                    | FeatureType::Gemini
                    | FeatureType::DiscovRE
                    | FeatureType::DGIS => {
                        let feature_vecs = feature_vecs.as_f64_mut().unwrap();
                        for bb in &self.blocks {
                            bb.get_block_edges(&bb_start_addrs, &mut edge_list);
                            bb.generate_bb_feature_vec(feature_vecs, feature_type, architecture);
                        }
                        debug!("Number of Feature Vecs: {}", feature_vecs.len());
                        assert_eq!(self.blocks.len(), feature_vecs.len())
                    }
                    FeatureType::Esil | FeatureType::Disasm | FeatureType::Pseudo => {
                        let feature_vecs = feature_vecs.as_string_mut().unwrap();
                        for bb in &self.blocks {
                            bb.get_block_edges(&bb_start_addrs, &mut edge_list);
                            bb.generate_bb_feature_strings(feature_vecs, feature_type, true);
                        }
                        debug!("Number of Feature Vecs: {}", feature_vecs.len());
                        assert_eq!(self.blocks.len(), feature_vecs.len())
                    }
                    FeatureType::ModelEmbedded | FeatureType::Encoded | FeatureType::Invalid => {
                        info!("Invalid Feature Type. Skipping..");
                        return;
                    }
                    _ => {}
                };

                debug!(
                    "Edge List Empty: {} Edge List Dims: {}",
                    edge_list.is_empty(),
                    edge_list.len()
                );

                if !edge_list.is_empty() {
                    let mut graph = Graph::<String, u32>::from_edges(&edge_list);
                    Self::str_to_hex_node_idxs(&mut graph, &bb_start_addrs);
                    if graph.node_count() != self.blocks.len() {
                        debug!("Graph for {} does not have the same number of nodes as basic blocks - N: {} B: {}. This suggests \
                        there is something wrong with the CFG edge recovery. If this is a problem, please raise a GitHub issue!",
                        self.name, graph.node_count(), self.blocks.len());
                        return;
                    }

                    // Unpack the NodeTypes to the inner Types
                    if feature_type == FeatureType::Gemini {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_f64().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<GeminiNode> =
                            NetworkxDiGraph::<GeminiNode>::from(networkx_graph);

                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else if feature_type == FeatureType::DGIS {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_f64().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<DGISNode> =
                            NetworkxDiGraph::<DGISNode>::from(networkx_graph);
                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else if feature_type == FeatureType::DiscovRE {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_f64().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<DiscovreNode> =
                            NetworkxDiGraph::<DiscovreNode>::from(networkx_graph);
                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else if feature_type == FeatureType::Tiknib {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_f64().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<TiknibNode> =
                            NetworkxDiGraph::<TiknibNode>::from(networkx_graph);
                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else if feature_type == FeatureType::Disasm {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_string().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<DisasmNode> =
                            NetworkxDiGraph::<DisasmNode>::from(networkx_graph);
                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else if feature_type == FeatureType::Esil {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_string().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<EsilNode> =
                            NetworkxDiGraph::<EsilNode>::from(networkx_graph);
                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else if feature_type == FeatureType::Pseudo {
                        let networkx_graph: NetworkxDiGraph<NodeType> =
                            NetworkxDiGraph::<NodeType>::from((
                                &graph,
                                feature_vecs.as_string().unwrap(),
                                feature_type,
                            ));

                        let networkx_graph_inners: NetworkxDiGraph<PseudoNode> =
                            NetworkxDiGraph::<PseudoNode>::from(networkx_graph);
                        info!("Saving to JSON..");
                        serde_json::to_writer(
                            &File::create(fname_string).expect("Failed to create writer"),
                            &networkx_graph_inners,
                        )
                        .expect("Unable to write JSON");
                    } else {
                        info!("Function {} has no edges. Skipping...", self.name)
                    }
                } else {
                    debug!(
                        "Function {} has less than the minimum number of blocks. Skipping..",
                        self.name
                    );
                }
            } else {
                trace!("Function has fewer basic blocks than the minimum. Skipping...");
            }
        } else {
            debug!(
                "Function {} has already been processed. Skipping...",
                self.name
            )
        }
    }

    // Convert string memory address to hex / string
    fn str_to_hex_node_idxs(graph: &mut Graph<String, u32>, addr_idxs: &[i64]) {
        for idx in graph.node_indices() {
            let i_idx = idx.index();
            let hex = addr_idxs[i_idx];
            graph[idx] = format!("{hex:#x} / {hex}");
        }
    }

    pub fn generate_tiknib_cfg_global_features(&self, architecture: &String) -> TikNibFunc {
        let mut basic_block_features = Vec::new();

        for block in &self.blocks {
            let feats = block.get_tiknib_features_bb(architecture);
            basic_block_features.push(feats)
        }

        TikNibFunc::from((&self.name, basic_block_features))
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
pub struct TikNibFunc {
    pub name: String,
    pub features: TikNibFuncFeatures,
}

impl Default for TikNibFunc {
    fn default() -> Self {
        TikNibFunc {
            name: "default".to_string(),
            features: TikNibFuncFeatures::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Hash, Serialize, Deserialize)]
pub struct TikNibFuncFeatures {
    // Averages
    pub avg_arithshift: OrderedFloat<f32>,
    pub avg_compare: OrderedFloat<f32>,
    pub avg_ctransfer: OrderedFloat<f32>,
    pub avg_ctransfercond: OrderedFloat<f32>,
    pub avg_dtransfer: OrderedFloat<f32>,
    pub avg_float: OrderedFloat<f32>,
    pub avg_total: OrderedFloat<f32>,
    // Sum
    pub sum_arithshift: OrderedFloat<f32>,
    pub sum_compare: OrderedFloat<f32>,
    pub sum_ctransfer: OrderedFloat<f32>,
    pub sum_ctransfercond: OrderedFloat<f32>,
    pub sum_dtransfer: OrderedFloat<f32>,
    pub sum_float: OrderedFloat<f32>,
    pub sum_total: OrderedFloat<f32>,
}

impl Default for TikNibFuncFeatures {
    fn default() -> Self {
        TikNibFuncFeatures {
            avg_arithshift: OrderedFloat(0.0),
            avg_compare: OrderedFloat(0.0),
            avg_ctransfer: OrderedFloat(0.0),
            avg_ctransfercond: OrderedFloat(0.0),
            avg_dtransfer: OrderedFloat(0.0),
            avg_float: OrderedFloat(0.0),
            avg_total: OrderedFloat(0.0),
            sum_arithshift: OrderedFloat(0.0),
            sum_compare: OrderedFloat(0.0),
            sum_ctransfer: OrderedFloat(0.0),
            sum_ctransfercond: OrderedFloat(0.0),
            sum_dtransfer: OrderedFloat(0.0),
            sum_float: OrderedFloat(0.0),
            sum_total: OrderedFloat(0.0),
        }
    }
}

// This is a bit odd but is to make sure the JSON output is formatted nice!
impl From<(&String, Vec<TikNibFeaturesBB>)> for TikNibFunc {
    fn from(input: (&String, Vec<TikNibFeaturesBB>)) -> Self {
        TikNibFunc {
            name: input.0.to_string(),
            features: TikNibFuncFeatures {
                avg_arithshift: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.arithshift).collect(),
                )),
                avg_compare: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.arithshift).collect(),
                )),
                avg_ctransfer: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.ctransfer).collect(),
                )),
                avg_ctransfercond: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.ctransfercond).collect(),
                )),
                avg_dtransfer: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.dtransfer).collect(),
                )),
                avg_float: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.float).collect(),
                )),
                avg_total: OrderedFloat::from(average(
                    input.1.iter().map(|ele| ele.total).collect(),
                )),
                sum_arithshift: OrderedFloat::from(
                    input.1.iter().map(|ele| ele.arithshift).sum::<f32>(),
                ),
                sum_compare: OrderedFloat::from(input.1.iter().map(|ele| ele.compare).sum::<f32>()),
                sum_ctransfer: OrderedFloat::from(
                    input.1.iter().map(|ele| ele.ctransfer).sum::<f32>(),
                ),
                sum_ctransfercond: OrderedFloat::from(
                    input.1.iter().map(|ele| ele.ctransfercond).sum::<f32>(),
                ),
                sum_dtransfer: OrderedFloat::from(
                    input.1.iter().map(|ele| ele.dtransfer).sum::<f32>(),
                ),
                sum_float: OrderedFloat::from(input.1.iter().map(|ele| ele.float).sum::<f32>()),
                sum_total: OrderedFloat::from(input.1.iter().map(|ele| ele.total).sum::<f32>()),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::bb::FeatureType;
    use std::path::PathBuf;

    use crate::AGFJFile;

    #[test]
    fn test_example_in_graph_rs() {
        assert_eq!(1, 1);
    }

    #[test]
    fn file_struct_creation() {
        let file_path = PathBuf::from("../sample-tool-outputs/r2/example_agfj@@F_output.json");
        let file = AGFJFile {
            functions: None,
            filename: file_path.to_owned(),
            output_path: PathBuf::from("output.json"),
            min_blocks: 5,
            feature_type: Some(crate::bb::FeatureType::Gemini),
            architecture: None,
            reg_norm: false,
        };

        assert!(file.functions.is_none());
        assert_eq!(
            file.filename,
            PathBuf::from("../sample-tool-outputs/r2/example_agfj@@F_output.json")
        );
        assert_eq!(file.output_path, PathBuf::from("output.json"));
        assert_eq!(file.min_blocks, 5);
        assert_eq!(file.feature_type, Some(FeatureType::Gemini));
    }

    #[test]
    fn test_file_load_and_desearlize() {
        let file_path = PathBuf::from("test-files/r2-output-samples/example_agfj@@F_output.json");
        let mut file = AGFJFile {
            functions: None,
            filename: file_path.to_owned(),
            output_path: PathBuf::from("output.json"),
            min_blocks: 5,
            feature_type: Some(crate::bb::FeatureType::Gemini),
            architecture: None,
            reg_norm: false,
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
        let file_path = PathBuf::from("test-files/r2-output-samples/test_bin_agfj.json");
        let mut file = AGFJFile {
            functions: None,
            filename: file_path.to_owned(),
            output_path: PathBuf::from("output.json"),
            min_blocks: 5,
            feature_type: Some(crate::bb::FeatureType::Gemini),
            architecture: None,
            reg_norm: false,
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
            (0, 2, 1),
            (0, 1, 1),
            (1, 3, 1),
            (2, 3, 1),
            (3, 5, 1),
            (3, 4, 1),
            (4, 8, 1),
            (5, 7, 1),
            (5, 6, 1),
            (6, 8, 1),
            (7, 8, 1),
        ]);

        assert_eq!(target_func.edge_list, expected_edge_list)
    }
}
