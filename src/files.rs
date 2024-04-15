use crate::afij::{AFIJFeatureSubset, AFIJFeatureSubsetExtended, AFIJFunctionInfo};
use crate::agcj::AGCJFunctionCallGraph;
use crate::agfj::{AGFJFunc, TikNibFunc};
use crate::bb::{FeatureType, InstructionMode};
use crate::consts::*;
use crate::errors::FileLoadError;
#[cfg(feature = "inference")]
use crate::inference::InferenceJob;
use crate::networkx::{
    CallGraphFuncWithMetadata, CallGraphTikNibFeatures, CallGraphTypes, NetworkxDiGraph,
};
use crate::utils::get_save_file_path;
use enum_as_inner::EnumAsInner;
use indicatif::ParallelProgressIterator;
use itertools::Itertools;

use crate::DataType;
use petgraph::{Graph, Incoming, Outgoing};
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::string::String;
use std::sync::mpsc::channel;
#[cfg(feature = "inference")]
use std::sync::Arc;
#[cfg(feature = "inference")]
use tch::nn::func;

#[derive(Serialize, Deserialize, Debug)]
pub struct AGFJFile {
    pub filename: PathBuf,
    pub functions: Option<Vec<Vec<AGFJFunc>>>,
    pub output_path: PathBuf,
    pub min_blocks: u16,
    pub feature_type: Option<FeatureType>,
    pub architecture: Option<String>,
    pub reg_norm: bool,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum FormatMode {
    SingleInstruction,
    FuncAsString,
    Invalid,
}

impl AGFJFile {
    // Allowed to enable propagation of errors from both reading to wstring and serde from str.
    #[allow(clippy::result_unit_err)]
    /// Loads and desearializes an AGFJ JSON file into a Vec<Vec<AGFJFunc>> and
    /// then detects the architecure of the functions stored within
    ///
    /// `agfj` is the radare2 command used to generate the `cfg` data. The code for this
    /// can be found in extract.rs.
    pub fn load_and_deserialize(&mut self) -> Result<(), ()> {
        let data = read_to_string(&self.filename).expect("Unable to read file");

        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json = serde_json::from_str(&data);

        if json.is_ok() {
            self.functions = Some(json.unwrap());

            self.architecture = self.detect_architecture();

            Ok(())
        } else {
            Err(())
        }
    }

    /// Detects the architecture of a file by iterating through the functions
    /// until a call instruction type is found. Once found, the opcode is then
    /// matched with architecture specific options.
    pub fn detect_architecture(&self) -> Option<String> {
        let mut call_op: Option<String> = None;

        for func in self.functions.as_ref().unwrap() {
            for block in &func[0].blocks {
                for op in &block.ops {
                    if op.r#type == "call" || op.r#type == "rcall" {
                        call_op = Some(op.disasm.as_ref().unwrap().clone())
                    }
                    if call_op.is_some() {
                        let opcode = call_op.as_ref().unwrap().split_whitespace().next().unwrap();
                        if X86_CALL.contains(&opcode) {
                            return Some("X86".to_string());
                        } else if ARM_CALL.contains(&opcode) {
                            return Some("ARM".to_string());
                        } else if MIPS_CALL.contains(&opcode) {
                            return Some("MIPS".to_string());
                        } else {
                            continue;
                        }
                    }
                }
            }
        }

        call_op
    }

    /// Executes a generation option based on provided inputs
    /// This acts as the primary public API for creating downstream
    /// data from an AGFJ extracted JSON file
    pub fn execute_data_generation(
        self,
        format_type: FormatMode,
        instruction_type: InstructionMode,
        random_walk: &bool,
        pairs: bool,
    ) {
        if format_type == FormatMode::SingleInstruction {
            if !(*random_walk) {
                if instruction_type == InstructionMode::Disasm {
                    self.generate_linear_bb_walk(false);
                } else if instruction_type == InstructionMode::ESIL {
                    self.generate_linear_bb_walk(true);
                }
            } else if instruction_type == InstructionMode::Disasm {
                self.generate_random_bb_walk(false, pairs);
            } else if instruction_type == InstructionMode::ESIL {
                self.generate_random_bb_walk(true, pairs);
            }
        } else if format_type == FormatMode::FuncAsString {
            if instruction_type == InstructionMode::Disasm {
                self.generate_disasm_func_strings();
            } else if instruction_type == InstructionMode::ESIL {
                self.generate_esil_func_strings();
            }
        }
    }

    /// Generates basic block level random walks
    ///
    /// This function iterates across the functions within a AGFJ
    /// file before collecting the random walks and saving them into a text
    /// file
    ///
    /// This function is useful for creating single instuction pre-training
    /// data where you want to do things like masked language modelling
    ///
    /// It is *not* suitable for doing any other sort of tasks such as Next Sentence
    /// Prediction (NSP) as there is not indication of where a basic block starts or ends.
    pub fn generate_random_bb_walk(mut self, esil: bool, pairs: bool) {
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None);
        let fname_string = if esil {
            format!("{:?}-esil-singles-rwdfs.txt", fname_string)
        } else {
            format!("{:?}-dis-singles-rwdfs.txt", fname_string)
        };

        if !Path::new(&fname_string).exists() {
            self.load_and_deserialize()
                .expect("Unable to load and desearilize JSON");

            let (sender, receiver) = channel();

            self.functions.unwrap().par_iter_mut().for_each_with(
                sender,
                |s, func: &mut Vec<AGFJFunc>| {
                    s.send(func[0].disasm_random_walks(
                        &self.min_blocks,
                        esil,
                        self.reg_norm,
                        pairs,
                    ))
                    .unwrap()
                },
            );

            let res = receiver.iter();

            let flattened: Vec<String> = res
                .into_iter()
                .flatten()
                .flatten()
                .flatten()
                .collect::<Vec<_>>()
                .into_iter()
                .collect();

            // TODO - Turn this into an info level log
            info!("Total Number of Lines: {:?}", flattened.len());

            let write_file = File::create(fname_string).unwrap();
            let mut writer = BufWriter::new(&write_file);

            writer.write_all(flattened.join("\n").as_bytes()).expect("");
        }
    }

    /// Generates a single string which contains the ESIL representation of every
    /// instruction within a function
    pub fn generate_esil_func_strings(mut self) {
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None);
        let fname_string = format!("{}-efs.json", fname_string.to_string_lossy());

        if !Path::new(&fname_string).exists() {
            self.load_and_deserialize()
                .expect("Unable to load and desearilize JSON");

            if self.functions.is_some() {
                let (sender, receiver) = channel();

                self.functions.unwrap().par_iter_mut().for_each_with(
                    sender,
                    |s, func: &mut Vec<AGFJFunc>| {
                        s.send(func[0].get_esil_function_string(&self.min_blocks, self.reg_norm))
                            .unwrap()
                    },
                );

                let res: Vec<Option<(String, String)>> = receiver.iter().collect();
                if !res.is_empty() {
                    let fixed: Vec<(String, String)> =
                        res.into_iter().filter(|x| x.is_some()).flatten().collect();
                    let map: HashMap<_, _> = fixed.into_iter().collect();

                    let json = json!(map);

                    serde_json::to_writer(
                        &File::create(fname_string).expect("Failed to create writer"),
                        &json,
                    )
                    .expect("Unable to write JSON");
                }
            }
        }
    }

    /// Generates a single string which contains the every instruction within a function
    pub fn generate_disasm_func_strings(mut self) {
        // This needs to be amended so that there is a AGFJFunc function
        // that returns a function as a func string.
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None);
        let fname_string = format!("{}-dfs.json", fname_string.to_string_lossy());

        if !Path::new(&fname_string).exists() {
            self.load_and_deserialize()
                .expect("Unable to load and desearilize JSON");

            if self.functions.is_some() {
                let (sender, receiver) = channel();

                self.functions
                    .unwrap()
                    .par_iter_mut()
                    .progress()
                    .for_each_with(sender, |s, func: &mut Vec<AGFJFunc>| {
                        s.send(func[0].get_disasm_function_string(&self.min_blocks, self.reg_norm))
                            .unwrap()
                    });

                let res: Vec<Option<(String, String)>> = receiver.iter().collect();
                let fixed: Vec<(String, String)> =
                    res.into_iter().filter(|x| x.is_some()).flatten().collect();
                let map: HashMap<_, _> = fixed.into_iter().collect();

                let json = json!(map);

                serde_json::to_writer(
                    &File::create(fname_string).expect("Failed to create writer"),
                    &json,
                )
                .expect("Unable to write JSON");
            }
        }
    }

    /// Generates a file containing every instruction within each of the functions
    /// within the AGFJFile.
    ///
    /// This ignores control flow and simple iterates the JSON objects from the top to
    /// the bottom.
    pub fn generate_linear_bb_walk(mut self, esil: bool) {
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None);
        let fname_string = if esil {
            format!("{}-esil-singles.txt", fname_string.to_string_lossy())
        } else {
            format!("{}-dis-singles.txt", fname_string.to_string_lossy())
        };

        if !Path::new(&fname_string).exists() {
            self.load_and_deserialize()
                .expect("Unable to load and desearlize JSON");

            let (sender, receiver) = channel();

            self.functions.unwrap().par_iter_mut().for_each_with(
                sender,
                |s, func: &mut Vec<AGFJFunc>| {
                    s.send(func[0].get_function_instructions(esil, &self.min_blocks, self.reg_norm))
                        .unwrap()
                },
            );

            let res: Vec<Vec<String>> = receiver.iter().filter(|x| x.is_some()).flatten().collect();

            let write_file = File::create(fname_string).unwrap();
            let mut writer = BufWriter::new(&write_file);

            for func in res {
                for bb in func {
                    writer
                        .write_all(bb.as_bytes())
                        .expect("Unable to write bytes.");
                    writer.write_all(b"\n").expect("Unable to write bytes.");
                }
            }
        }
    }

    /// Generate Attributed Control Flow Graph (ACFG)'s for each of the functions
    /// within an AGFJFile.
    pub fn paralell_attributed_cfg_gen(self) {
        self.functions.unwrap().par_iter().for_each(|func| {
            func[0].generate_attributed_cfg(
                &self.filename,
                &self.min_blocks,
                &self.output_path,
                self.feature_type.unwrap(),
                self.architecture.as_ref().unwrap(),
            )
        });
    }

    pub fn tiknib_func_level_feature_gen(self) {
        let arch = self.detect_architecture();

        let mut func_feature_vectors = Vec::new();

        for func in self.functions.unwrap().iter() {
            let feature_vec = func[0].generate_tiknib_cfg_global_features(arch.as_ref().unwrap());
            func_feature_vectors.push(feature_vec);
        }

        let json = json!(&func_feature_vectors);
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None);
        let fname_string = format!("{}-tiknib.json", fname_string.to_string_lossy());
        serde_json::to_writer(
            &File::create(fname_string).expect("Failed to create writer"),
            &json,
        )
        .expect("Unable to write JSON");
    }

    /// EXPERIMENTAL
    ///
    /// Generate a CFG where each basic blocks contents is embedded using a provided
    /// machine learning model (represented as an InferenceJob)
    #[cfg(feature = "inference")]
    pub fn parallel_embedded_cfg_gen(mut self, inference_job: Option<Arc<InferenceJob>>) {
        self.load_and_deserialize()
            .expect("Unable to load and desearilize JSON");

        if inference_job.is_some() {
            self.functions.unwrap().par_iter().for_each(|func| {
                func[0].generate_embedded_cfg(
                    &self.filename,
                    &self.min_blocks,
                    &self.output_path,
                    self.feature_type.unwrap(),
                    &inference_job,
                )
            });
        }
    }
}

#[derive(Debug, Deserialize, Serialize, EnumAsInner)]
#[serde(untagged)]
pub enum FunctionMetadataTypes {
    AFIJ(Vec<AFIJFeatureSubset>),
    AFIJExtended(Vec<AFIJFeatureSubsetExtended>),
    AGFJ(Vec<TikNibFunc>),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AGCJFile {
    pub filename: PathBuf,
    pub function_call_graphs: Option<Vec<AGCJFunctionCallGraph>>,
    pub output_path: PathBuf,
    pub function_metadata: Option<FunctionMetadataTypes>,
    pub include_unk: bool,
}

impl AGCJFile {
    pub fn load_and_deserialize(&mut self) -> Result<(), FileLoadError> {
        let data = read_to_string(&self.filename)?;

        #[allow(clippy::expect_fun_call)]
        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json: Vec<AGCJFunctionCallGraph> = serde_json::from_str(&data)?;

        self.function_call_graphs = Some(json);
        Ok(())
    }

    // Global Call Graph Related Functions
    pub fn generate_global_call_graphs(&mut self, metadata_type: Option<String>) {
        let call_graph = self.build_global_call_graph();
        debug!("Num Nodes (Default): {}", call_graph.node_count());
        let cleaned_graph = self.post_process_graph(call_graph);
        debug!("Num Nodes (Post-Clean): {}", cleaned_graph.node_count());
        self.save_global_call_graph_to_json(cleaned_graph, metadata_type)
    }

    fn build_global_call_graph(&mut self) -> Graph<String, u32> {
        if self.function_call_graphs.is_none() {
            let ret = self.load_and_deserialize();
            if ret.is_err() {
                error!("Unable to load target data file - No functions to process.")
            }
        }

        let mut graph = Graph::<String, u32>::new();

        for function in self.function_call_graphs.as_ref().unwrap().iter() {
            let function_index_find = graph.node_indices().find(|i| graph[*i] == function.name);

            let function_index = if let Some(index) = function_index_find {
                index
            } else {
                graph.add_node(function.name.clone())
            };

            debug!(
                "Function Index Find: {:?} Function Index Used: {:?}",
                function_index_find, function_index
            );

            if function.imports.is_some() {
                for import in function.imports.as_ref().unwrap().iter() {
                    if !self.include_unk && import.starts_with("unk.") {
                        debug!("Skipping {}", import);
                        continue;
                    } else {
                        let import_index_find = graph.node_indices().find(|i| &graph[*i] == import);
                        let import_index = if let Some(index) = import_index_find {
                            index
                        } else {
                            graph.add_node(import.clone())
                        };

                        graph.update_edge(function_index, import_index, 0);
                    }
                }
            }
        }
        graph
    }

    fn post_process_graph(&self, mut graph: Graph<String, u32>) -> Graph<String, u32> {
        // Tidy up the generated call graph to account for when
        // calling relationships may have not been recovered and
        // we have orphan nodes
        for node_idx in graph.node_indices() {
            if graph
                .neighbors_directed(node_idx, Outgoing)
                .collect_vec()
                .len()
                + graph
                    .neighbors_directed(node_idx, Incoming)
                    .collect_vec()
                    .len()
                == 0
            {
                graph.remove_node(node_idx);
            }
        }
        graph
    }

    fn add_node_features_to_global_call_graph(
        &self,
        graph: Graph<String, u32>,
        metadata_type: Option<String>,
    ) -> CallGraphTypes {
        match metadata_type.unwrap().as_str() {
            "finfo" => {
                let networkx_graph = NetworkxDiGraph::<CallGraphFuncWithMetadata>::from((
                    graph,
                    self.function_metadata.as_ref().unwrap().as_afij().unwrap(),
                ));
                CallGraphTypes::CGMeta(networkx_graph)
            }
            "tiknib" => {
                let networkx_graph = NetworkxDiGraph::<CallGraphTikNibFeatures>::from((
                    graph,
                    self.function_metadata.as_ref().unwrap().as_agfj().unwrap(),
                ));
                CallGraphTypes::TikNib(networkx_graph)
            }
            _ => unreachable!("Impossible :D"),
        }
    }
    fn save_global_call_graph_to_json(
        &self,
        graph: Graph<String, u32>,
        metadata_type: Option<String>,
    ) {
        let networkx_graph = if metadata_type.is_some() {
            self.add_node_features_to_global_call_graph(graph, metadata_type)
        } else {
            CallGraphTypes::CGName(NetworkxDiGraph::from(graph))
        };

        let mut full_output_path = get_save_file_path(
            &self.filename,
            &self.output_path,
            Some("gcg".to_string()),
            Some("_cg".to_string()),
        );

        full_output_path.set_extension("json");

        debug!(
            "Attempting to save global call graph to: {:?}",
            full_output_path
        );

        serde_json::to_writer(
            &File::create(full_output_path).expect("Failed to create writer"),
            &networkx_graph,
        )
        .expect("Unable to write JSON");
    }

    // Local Call Graph Helper Functions
    fn process_function_level_cg(
        &self,
        graph_data_type: DataType,
        with_features: &bool,
        metadata_type: Option<String>,
    ) {
        for fcg in self.function_call_graphs.as_ref().unwrap() {
            match graph_data_type {
                DataType::Cg => {
                    fcg.to_petgraph(
                        self,
                        &self.output_path,
                        &self.filename,
                        with_features,
                        &self.include_unk,
                        metadata_type.clone(),
                    );
                }
                DataType::OneHopCg => {
                    fcg.one_hop_to_petgraph(
                        self,
                        &self.output_path,
                        &self.filename,
                        with_features,
                        &self.include_unk,
                        metadata_type.clone(),
                    );
                }
                DataType::CgWithCallers => {
                    fcg.to_petgraph_with_callers(
                        self,
                        &self.output_path,
                        &self.filename,
                        with_features,
                        &self.include_unk,
                        metadata_type.clone(),
                    );
                }
                DataType::OneHopCgWithcallers => {
                    fcg.one_hop_to_petgraph_with_callers(
                        self,
                        &self.output_path,
                        &self.filename,
                        with_features,
                        &self.include_unk,
                        metadata_type.clone(),
                    );
                }
                _ => unreachable!("Not possible hopefully! :O"),
            }
        }
    }

    pub fn process_based_on_graph_data_type(
        &mut self,
        graph_data_type: DataType,
        with_features: &bool,
        metadata_type: Option<String>,
    ) {
        match graph_data_type {
            DataType::GlobalCg => self.generate_global_call_graphs(metadata_type.clone()),
            DataType::Cg
            | DataType::OneHopCg
            | DataType::OneHopCgWithcallers
            | DataType::CgWithCallers => self.process_function_level_cg(
                graph_data_type,
                with_features,
                metadata_type.clone(),
            ),
            _ => unreachable!("Unreachable!"),
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AFIJFile {
    pub filename: PathBuf,
    pub function_info: Option<Vec<AFIJFunctionInfo>>,
    pub output_path: PathBuf,
}

impl AFIJFile {
    pub fn load_and_deserialize(&mut self) -> Result<(), FileLoadError> {
        let data = read_to_string(&self.filename)?;

        #[allow(clippy::expect_fun_call)]
        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json: Vec<AFIJFunctionInfo> = serde_json::from_str(&data)?;

        self.function_info = Some(json);
        Ok(())
    }

    pub fn subset(&mut self, extended: bool) -> FunctionMetadataTypes {
        if extended {
            let mut func_info_subsets_extended: Vec<AFIJFeatureSubsetExtended> = Vec::new();
            debug!("Starting to subset functions");
            for function in self.function_info.as_ref().unwrap().iter() {
                let subset = AFIJFeatureSubsetExtended::from(function);
                func_info_subsets_extended.push(subset)
            }
            FunctionMetadataTypes::AFIJExtended(func_info_subsets_extended)
        } else {
            let mut func_info_subsets: Vec<AFIJFeatureSubset> = Vec::new();
            debug!("Starting to subset functions");
            for function in self.function_info.as_ref().unwrap().iter() {
                let subset = AFIJFeatureSubset::from(function);
                func_info_subsets.push(subset)
            }
            FunctionMetadataTypes::AFIJ(func_info_subsets)
        }
    }
    pub fn subset_and_save(&mut self, extended: bool) {
        let func_info_subsets = self.subset(extended);
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None);
        let filename = format!("{}-finfo-subset.json", fname_string.to_string_lossy());
        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &func_info_subsets,
        )
        .expect("Unable to write JSON");
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct TikNibFuncMetaFile {
    pub filename: PathBuf,
    pub function_info: Option<Vec<TikNibFunc>>,
    pub output_path: PathBuf,
}

impl TikNibFuncMetaFile {
    pub fn load_and_deserialize(&mut self) -> Result<(), FileLoadError> {
        let data = read_to_string(&self.filename)?;

        #[allow(clippy::expect_fun_call)]
        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json: Vec<TikNibFunc> = serde_json::from_str(&data)?;

        self.function_info = Some(json);
        Ok(())
    }

    pub fn subset(&mut self) -> FunctionMetadataTypes {
        FunctionMetadataTypes::AGFJ(self.function_info.clone().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::files::AGCJFile;
    use std::collections::HashSet;
    use std::path::PathBuf;

    fn return_test_file_oject(file_path: &str) -> AGCJFile {
        let mut call_graph_file = AGCJFile {
            filename: PathBuf::from(file_path),
            function_call_graphs: None,
            output_path: PathBuf::new(),
            function_metadata: None,
            include_unk: false,
        };

        call_graph_file
            .load_and_deserialize()
            .expect("Failed to load data");
        call_graph_file
    }

    #[test]
    fn test_global_call_graph_generation() {
        let mut call_graph_file = return_test_file_oject("test-files/ls_cg.json");

        let global_call_graph = call_graph_file.build_global_call_graph();

        assert_eq!(global_call_graph.node_count(), 111);

        let mut node_names = Vec::new();

        for node in global_call_graph.raw_nodes().iter() {
            node_names.push(node.weight.clone())
        }

        let unique_node_names = node_names.iter().collect::<HashSet<_>>();

        assert_eq!(node_names.len(), unique_node_names.len());
    }

    #[test]
    fn test_global_graph_with_redudent_nodes() {
        let mut call_graph_file = return_test_file_oject("data-examples/raw/test_bin_cg.json");

        let global_call_graph = call_graph_file.build_global_call_graph();

        assert_eq!(global_call_graph.node_count(), 9);

        let mut node_names = Vec::new();

        for node in global_call_graph.raw_nodes().iter() {
            node_names.push(node.weight.clone())
        }

        let unique_node_names = node_names.iter().collect::<HashSet<_>>();

        assert_eq!(node_names.len(), unique_node_names.len());

        let post_processed_call_graph = call_graph_file.post_process_graph(global_call_graph);

        assert_eq!(post_processed_call_graph.node_count(), 8);

        let mut node_names = Vec::new();

        for node in post_processed_call_graph.raw_nodes().iter() {
            node_names.push(node.weight.clone())
        }

        let unique_node_names = node_names.iter().collect::<HashSet<_>>();

        assert_eq!(node_names.len(), unique_node_names.len());
    }
}
