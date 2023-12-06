use crate::afij::{AFIJFeatureSubset, AFIJFunctionInfo};
use crate::agcj::AGCJFunctionCallGraphs;
use crate::agfj::AGFJFunc;
use crate::bb::{FeatureType, InstructionMode};
use crate::consts::*;
use crate::errors::FileLoadError;
#[cfg(feature = "inference")]
use crate::inference::InferenceJob;
use crate::utils::get_save_file_path;
use indicatif::ParallelProgressIterator;
use rayon::iter::ParallelIterator;
use rayon::prelude::{IntoParallelRefIterator, IntoParallelRefMutIterator};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::string::String;
use std::sync::mpsc::channel;
#[cfg(feature = "inference")]
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug)]
pub struct AGFJFile {
    pub filename: String,
    pub functions: Option<Vec<Vec<AGFJFunc>>>,
    pub output_path: String,
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

        #[allow(clippy::expect_fun_call)]
        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json: Vec<Vec<AGFJFunc>> = serde_json::from_str(&data).expect(&format!(
            "Unable to load function data from {}",
            self.filename
        ));

        self.functions = Some(json);

        self.architecture = self.detect_architecture();

        Ok(())
    }

    /// Detects the architecture of a file by iterating through the functions
    /// until a call instruction type is found. Once found, the opcode is then
    /// matched with architecture specific options.
    fn detect_architecture(&self) -> Option<String> {
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
        let fname_string: String = get_save_file_path(&self.filename, &self.output_path, None);
        let fname_string = if esil {
            format!("{}-esil-singles-rwdfs.txt", fname_string)
        } else {
            format!("{}-dis-singles-rwdfs.txt", fname_string)
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
        let fname_string: String = get_save_file_path(&self.filename, &self.output_path, None);
        let fname_string = format!("{}-efs.json", fname_string);

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
        let fname_string: String = get_save_file_path(&self.filename, &self.output_path, None);
        let fname_string = format!("{}-dfs.json", fname_string);

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
                let fname_string: String =
                    get_save_file_path(&self.filename, &self.output_path, None);
                let fname_string = format!("{}-dfs.json", fname_string);

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
        let fname_string: String = get_save_file_path(&self.filename, &self.output_path, None);
        let fname_string = if esil {
            format!("{}-esil-singles.txt", fname_string)
        } else {
            format!("{}-dis-singles.txt", fname_string)
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

#[derive(Serialize, Deserialize, Debug)]
pub struct AGCJFile {
    pub filename: String,
    pub function_call_graphs: Option<Vec<AGCJFunctionCallGraphs>>,
    pub output_path: String,
    pub function_metadata: Option<Vec<AFIJFeatureSubset>>,
}

impl AGCJFile {
    pub fn load_and_deserialize(&mut self) -> Result<(), FileLoadError> {
        let data = read_to_string(&self.filename)?;

        #[allow(clippy::expect_fun_call)]
        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json: Vec<AGCJFunctionCallGraphs> = serde_json::from_str(&data)?;

        self.function_call_graphs = Some(json);
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AFIJFile {
    pub filename: String,
    pub function_info: Option<Vec<AFIJFunctionInfo>>,
    pub output_path: String,
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

    pub fn subset(&mut self) -> Vec<AFIJFeatureSubset> {
        let mut func_info_subsets: Vec<AFIJFeatureSubset> = Vec::new();
        debug!("Starting to subset functions");
        for function in self.function_info.as_ref().unwrap().iter() {
            let subset = AFIJFeatureSubset::from(function);
            func_info_subsets.push(subset)
        }
        func_info_subsets
    }
    pub fn subset_and_save(&mut self) {
        let func_info_subsets = self.subset();
        let fname_string: String = get_save_file_path(&self.filename, &self.output_path, None);
        let filename = format!("{}-finfo-subset.json", fname_string);
        serde_json::to_writer(
            &File::create(filename).expect("Failed to create writer"),
            &func_info_subsets,
        )
        .expect("Unable to write JSON");
    }
}
