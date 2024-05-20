use crate::afij::AFIJFunctionInfo;
use crate::agcj::AGCJFunctionCallGraph;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Error;
use anyhow::Result;
use r2pipe::R2Pipe;
use r2pipe::R2PipeSpawnOptions;

use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_json;

use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;

use std::fs;
use std::fs::File;

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(PartialEq, Debug)]
pub enum PathType {
    File,
    Dir,
    Unk,
}
#[derive(Debug, PartialEq)]
pub enum ExtractionJobType {
    // bininfo is not implemented in anyway
    BinInfo, // Extract high level information from the binary (r2 ij)
    BasicBlocks,
    RegisterBehaviour,
    FunctionXrefs,
    CFG,
    CallGraphs,
    FuncInfo,
    Decompilation,
    PCodeFunc,
    PCodeBB,
    LocalVariableXrefs,
}

#[derive(Debug)]
pub struct FileToBeProcessed {
    pub file_path: PathBuf,
    pub output_path: PathBuf,
    pub job_type_suffix: String,
    pub r2p_config: R2PipeConfig,
    pub with_annotations: bool,
}

#[derive(Debug)]
pub struct ExtractionJob {
    pub input_path: PathBuf,
    pub input_path_type: PathType,
    pub job_type: ExtractionJobType,
    pub files_to_be_processed: Vec<FileToBeProcessed>,
    pub output_path: PathBuf, // Remove - Kept for backwards compat
}

#[derive(Debug, Clone, Copy)]
pub struct R2PipeConfig {
    pub debug: bool,
    pub extended_analysis: bool,
    pub use_curl_pdb: bool,
}

impl std::fmt::Display for ExtractionJob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "bin_path: {:?} p_type: {:?} what_do: {:?}",
            self.input_path, self.input_path_type, self.job_type
        )
    }
}

// Structs related to AFLJ r2 command
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AFLJFuncDetails {
    pub offset: u64,
    pub name: String,
    pub size: u64,
    #[serde(rename = "is-pure")]
    pub is_pure: String,
    pub realsz: u64,
    pub noreturn: bool,
    pub stackframe: u64,
    pub calltype: String,
    pub cost: u64,
    pub cc: u64,
    pub bits: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub nbbs: u64,
    #[serde(rename = "is-lineal")]
    pub is_lineal: bool,
    pub ninstrs: u64,
    pub edges: u64,
    pub ebbs: u64,
    pub signature: String,
    pub minbound: i64,
    pub maxbound: u64,
    #[serde(default)]
    pub callrefs: Vec<Callref>,
    #[serde(default)]
    pub datarefs: Vec<DataRef>,
    pub indegree: Option<u64>,
    pub outdegree: Option<u64>,
    pub nlocals: Option<u64>,
    pub nargs: Option<u64>,
    pub bpvars: Option<Vec<Bpvar>>,
    pub spvars: Option<Vec<Value>>,
    pub regvars: Option<Vec<Regvar>>,
    pub difftype: Option<String>,
    #[serde(default)]
    pub codexrefs: Option<Vec<Codexref>>,
    #[serde(default)]
    pub dataxrefs: Option<Vec<u64>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", transparent)]
pub struct DataRef {
    #[serde(deserialize_with = "deserialize_string_from_number")]
    value: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callref {
    pub addr: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bpvar {
    pub name: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "ref")]
    pub ref_field: Ref,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ref {
    pub base: String,
    pub offset: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Regvar {
    pub name: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "ref")]
    pub ref_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Codexref {
    pub addr: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: u64,
}

// Structs related to AEAFJ
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AEAFJRegisterBehaviour {
    #[serde(rename = "A")]
    pub a: Vec<String>,
    #[serde(rename = "I")]
    pub i: Vec<String>,
    #[serde(rename = "R")]
    pub r: Vec<String>,
    #[serde(rename = "W")]
    pub w: Vec<String>,
    #[serde(rename = "V")]
    pub v: Vec<String>,
    #[serde(rename = "N")]
    #[serde(default)]
    pub n: Vec<String>,
    #[serde(rename = "@R")]
    #[serde(default)]
    pub r2: Vec<u64>,
    #[serde(rename = "@W")]
    #[serde(default)]
    pub w2: Vec<u64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
// Created using the axffj command
pub struct FunctionXrefDetails {
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
    #[serde(rename = "ref")]
    pub ref_field: i128,
    pub name: String,
}

impl std::fmt::Display for AFLJFuncDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "name: {}", self.name)
    }
}

impl From<(String, String, String, R2PipeConfig, bool)> for FileToBeProcessed {
    fn from(orig: (String, String, String, R2PipeConfig, bool)) -> FileToBeProcessed {
        FileToBeProcessed {
            file_path: PathBuf::from(orig.0),
            output_path: PathBuf::from(orig.1),
            job_type_suffix: orig.2,
            r2p_config: orig.3,
            with_annotations: orig.4,
        }
    }
}

// Structs for pdgj - Ghidra Decomp JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecompJSON {
    pub code: String,
    pub annotations: Vec<Annotation>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Annotation {
    pub start: i64,
    pub end: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub syntax_highlight: Option<String>,
    pub name: Option<String>,
    pub offset: Option<i64>,
}

// Structs  for pdgsd - Ghidra PCode JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJSON {
    pub pcode: Vec<String>,
    pub asm: Option<Vec<String>>,
}

// Structs for pdgsd + basic block connectivity - Ghidra PCode JSON Output + afbj
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJsonWithBB {
    pub pcode: Vec<String>,
    pub asm: Option<Vec<String>>,
    pub bb_info: BasicBlockEntry,
}

// Structs for afbj - Basic Block JSON output
pub type BasicBlockInfo = Vec<BasicBlockEntry>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlockEntry {
    pub addr: i64,
    pub size: i64,
    pub jump: Option<i64>,
    pub fail: Option<i64>,
    pub opaddr: f64,
    pub inputs: i64,
    pub outputs: i64,
    pub ninstr: i64,
    pub instrs: Vec<i64>,
    pub traced: bool,
}

// Structs for axvj - Local Variable Xref JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LocalVariableXrefs {
    pub reads: Vec<Reads>,
    pub writes: Vec<Writes>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Reads {
    pub name: String,
    pub addrs: Vec<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Writes {
    pub name: String,
    pub addrs: Vec<i64>,
}

impl ExtractionJob {
    pub fn new(
        input_path: &PathBuf,
        output_path: &PathBuf,
        mode: &str,
        debug: &bool,
        extended_analysis: &bool,
        use_curl_pdb: &bool,
        with_annotations: &bool,
    ) -> Result<ExtractionJob, Error> {
        fn get_path_type(bin_path: &PathBuf) -> PathType {
            let fpath_md = fs::metadata(bin_path).unwrap();
            if fpath_md.is_file() {
                PathType::File
            } else if fpath_md.is_dir() {
                PathType::Dir
            } else {
                PathType::Unk
            }
        }

        // This functionality is currently not being used!
        fn extraction_job_matcher(mode: &str) -> Result<ExtractionJobType, Error> {
            match mode {
                // These aren't implemented
                //"bb" => Ok(ExtractionJobType::BasicBlocks),
                "finfo" => Ok(ExtractionJobType::FuncInfo),
                "reg" => Ok(ExtractionJobType::RegisterBehaviour),
                "cfg" => Ok(ExtractionJobType::CFG),
                "func-xrefs" => Ok(ExtractionJobType::FunctionXrefs),
                "cg" => Ok(ExtractionJobType::CallGraphs),
                "decomp" => Ok(ExtractionJobType::Decompilation),
                "pcode-func" => Ok(ExtractionJobType::PCodeFunc),
                "pcode-bb" => Ok(ExtractionJobType::PCodeBB),
                "localvar-xrefs" => Ok(ExtractionJobType::LocalVariableXrefs),
                _ => bail!("Incorrect command type - got {}", mode),
            }
        }

        let r2_handle_config = R2PipeConfig {
            debug: *debug,
            extended_analysis: *extended_analysis,
            use_curl_pdb: *use_curl_pdb,
        };

        let p_type = get_path_type(input_path);
        let job_type = extraction_job_matcher(mode).unwrap();

        if job_type != ExtractionJobType::Decompilation && *with_annotations {
            warn!("Annotations are only supported for decompilation extraction")
        };

        if p_type == PathType::File {
            let file = FileToBeProcessed {
                file_path: input_path.to_owned(),
                output_path: output_path.to_owned(),
                job_type_suffix: (*mode).to_string(),
                r2p_config: r2_handle_config,
                with_annotations: *with_annotations,
            };
            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: p_type,
                job_type,
                files_to_be_processed: vec![file],
                output_path: output_path.to_owned(),
            })
        } else if p_type == PathType::Dir {
            let files = ExtractionJob::get_file_paths_dir(input_path);

            let files_with_output_path: Vec<(String, String, String, R2PipeConfig, bool)> = files
                .into_iter()
                .map(|f| {
                    (
                        f,
                        output_path.to_string_lossy().to_string(),
                        mode.to_string(),
                        r2_handle_config,
                        with_annotations.clone(),
                    )
                })
                .collect();
            let files_to_be_processed: Vec<FileToBeProcessed> = files_with_output_path
                .into_iter()
                .map(FileToBeProcessed::from)
                .collect();
            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: p_type,
                job_type,
                files_to_be_processed,
                output_path: output_path.to_owned(),
            })
        } else {
            bail!("Failed to create extraction job.")
        }
    }

    fn get_file_paths_dir(input_path: &PathBuf) -> Vec<String> {
        let mut str_vec: Vec<String> = Vec::new();
        for file in WalkDir::new(input_path)
            .into_iter()
            .filter_map(|file| file.ok())
        {
            if file.metadata().unwrap().is_file()
                && !file.file_name().to_string_lossy().ends_with(".json")
            {
                let f_string =
                    String::from(<&std::path::Path>::clone(&file.path()).to_str().unwrap());
                str_vec.push(f_string.clone());
            }
        }
        str_vec
    }
}

impl FileToBeProcessed {
    pub fn extract_register_behaviour(&self) {
        info!("Starting register behaviour extraction");
        let mut r2p = self.setup_r2_pipe();
        let function_details = self.get_function_name_list(&mut r2p);
        if function_details.is_ok() {
            let mut register_behaviour_vec: HashMap<String, AEAFJRegisterBehaviour> =
                HashMap::new();
            info!("Executing aeafj for each function");
            for function in function_details.unwrap().iter() {
                r2p.cmd(format!("s @ {}", &function.name).as_str())
                    .expect("Command failed..");
                let json = r2p.cmd("aeafj").expect("Command failed..");
                let json_obj: AEAFJRegisterBehaviour =
                    serde_json::from_str(&json).expect("Unable to convert to JSON object!");
                register_behaviour_vec.insert(function.name.clone(), json_obj);
            }
            info!("All functions processed");
            r2p.close();
            info!("r2p closed");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(register_behaviour_vec))
        } else {
            error!(
                "Failed to extract function details to generate register behaviour - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_func_cfgs(&self) {
        let mut fp_filename = Path::new(&self.file_path)
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();
        fp_filename = fp_filename + "_" + &self.job_type_suffix.clone();
        let f_name = format!("{:?}/{}.json", &self.output_path, fp_filename);
        if !Path::new(&f_name).exists() {
            info!("{} not found. Continuing processing.", f_name);
            let mut r2p = self.setup_r2_pipe();
            info!("Executing agfj @@f on {:?}", self.file_path);
            let mut json = r2p
                .cmd("agfj @@f")
                .expect("Failed to extract control flow graph information.");
            info!("Closing r2p process for {:?}", self.file_path);
            r2p.close();
            info!("Starting JSON fixup for {:?}", self.file_path);
            // Fix JSON object
            json = json.replace("[]\n", ",");
            json = json.replace("}]\n[{", "}],\n[{");
            json.insert(0, '[');
            json.push(']');
            json = json.replace("}]\n,]", "}]\n]");
            json = json.replace("\n,,[{", "\n,[{");
            json = json.replace("\n,,[{", "\n,[{");
            info!("JSON fixup finished for {:?}", self.file_path);

            if json != "[,]" {
                #[allow(clippy::expect_fun_call)]
                // Kept in to ensure that the JSON decode error message is printed alongside the filename
                let json: Value = serde_json::from_str(&json).expect(&format!(
                    "Unable to parse json for {}: {}",
                    fp_filename, json
                ));

                self.write_to_json(&json);
            } else {
                error!(
                    "File empty after JSON fixup - Only contains [,] - {}",
                    f_name
                )
            }
        } else {
            info!("{} as already exists. Skipping", f_name)
        }
    }

    pub fn extract_function_call_graphs(&self) {
        info!("Starting function call graph extraction");
        let mut r2p = self.setup_r2_pipe();
        let json = r2p.cmd("agCj").expect("agCj command failed to execute");
        let function_call_graphs: Vec<AGCJFunctionCallGraph> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        info!("Function call graph extracted.");
        r2p.close();
        info!("r2p closed");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_call_graphs))
    }

    pub fn extract_function_xrefs(&self) {
        let mut r2p = self.setup_r2_pipe();
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_xrefs: HashMap<String, Vec<FunctionXrefDetails>> = HashMap::new();
        info!("Extracting xrefs for each function");
        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_function_xref_details(function.offset, &mut r2p);
                function_xrefs.insert(function.name.clone(), ret);
            }
            info!("All functions processed");
            r2p.close();
            info!("r2p closed");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_xrefs))
        } else {
            error!(
                "Failed to extract function xrefs - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_function_info(&self) {
        info!("Starting function metdata extraction");
        let mut fp_filename = self
            .file_path
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();

        fp_filename = fp_filename + "_" + &self.job_type_suffix.clone();
        let f_name = format!("{:?}/{}.json", self.output_path, fp_filename);
        if !Path::new(&f_name).exists() {
            let mut r2p = self.setup_r2_pipe();

            let function_details: Result<Vec<AFIJFunctionInfo>, r2pipe::Error> =
                self.get_function_name_list(&mut r2p);

            if function_details.is_err() {
                error!("Unable to extract function info for {:?}", self.file_path);
                r2p.close();
                info!("r2p closed");
            } else {
                r2p.close();
                info!("r2p closed");

                info!("Writing extracted data to file");
                self.write_to_json(&json!(function_details.unwrap()))
            }
        }
    }

    pub fn extract_decompilation(&self) {
        info!("Starting decompilation extraction!");
        let mut r2p = self.setup_r2_pipe();
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_decomp: HashMap<String, DecompJSON> = HashMap::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_ghidra_decomp(function.offset, &mut r2p);
                function_decomp.insert(function.name.clone(), ret.unwrap());
            }
            info!("Decompilation extracted successfully for all functions.");
            r2p.close();
            info!("r2p closed");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_decomp))
        } else {
            error!(
                "Failed to extract function decompilation - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_pcode_function(&self) {
        info!("Starting pcode extraction at a function level");
        let mut r2p = self.setup_r2_pipe();
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_pcode: HashMap<String, PCodeJSON> = HashMap::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret =
                    self.get_ghidra_pcode_function(function.offset, function.ninstrs, &mut r2p);
                function_pcode.insert(function.name.clone(), ret.unwrap());
            }
            info!("Pcode extracted successfully for all functions.");
            r2p.close();
            info!("r2p closed");
            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_pcode))
        } else {
            error!(
                "Failed to extract function decompilation - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_pcode_basic_block(&self) {
        info!("Starting pcode extraction for each basic block in each function within the binary");
        let mut r2p = self.setup_r2_pipe();
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_pcode: HashMap<String, HashMap<String, PCodeJsonWithBB>> = HashMap::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let bb_addresses = self.get_basic_block_addresses(function.offset, &mut r2p);
                let mut bb_pcode: HashMap<String, PCodeJsonWithBB> = HashMap::new();
                for bb in bb_addresses.unwrap().iter() {
                    let ret = self.get_ghidra_pcode_function(bb.addr as u64, bb.ninstr, &mut r2p);
                    if ret.is_ok() {
                        let ret = ret.unwrap();
                        let pcode_json = PCodeJsonWithBB {
                            pcode: ret.pcode,
                            asm: ret.asm,
                            bb_info: bb.clone(),
                        };
                        bb_pcode.insert(bb.addr.to_string(), pcode_json);
                    }
                }

                function_pcode.insert(function.name.clone(), bb_pcode);
            }
            info!("Pcode extracted successfully for all functions.");
            r2p.close();
            info!("r2p closed");
            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_pcode))
        } else {
            error!(
                "Failed to extract function decompilation - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_local_variable_xrefs(&self) {
        info!("Starting local variable xref extraction");
        let mut r2p = self.setup_r2_pipe();
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_local_variable_xrefs: HashMap<String, LocalVariableXrefs> = HashMap::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_local_variable_xref_details(function.offset, &mut r2p);
                function_local_variable_xrefs.insert(function.name.clone(), ret.unwrap());
            }
            info!("Local variable xrefs extracted successfully for all functions.");
            r2p.close();
            info!("r2p closed");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_local_variable_xrefs))
        } else {
            error!(
                "Failed to extract local variable xrefs - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    // r2 commands to structs
    fn get_ghidra_pcode_function(
        &self,
        function_addr: u64,
        num_instructons: i64,
        r2p: &mut R2Pipe,
    ) -> Result<PCodeJSON, r2pipe::Error> {
        Self::go_to_address(r2p, function_addr);
        let pcode_ret = r2p.cmd(format!("pdgsd {}", num_instructons).as_str())?;
        let lines = pcode_ret.lines();
        let mut asm_ins = Vec::new();
        let mut pcode_ins = Vec::new();

        for line in lines {
            if line.starts_with("0x") {
                asm_ins.push(line.trim().to_string());
            } else {
                pcode_ins.push(line.trim().to_string());
            }
        }

        Ok(PCodeJSON {
            pcode: pcode_ins,
            asm: Some(asm_ins),
        })
    }

    fn get_ghidra_decomp(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<DecompJSON, r2pipe::Error> {
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("pdgj")?;

        if self.with_annotations {
            let json_obj: DecompJSON =
                serde_json::from_str(&json).expect("Unable to convert to JSON object!");
            Ok(json_obj)
        } else {
            let json_obj: Value =
                serde_json::from_str(&json).expect("Unable to convert to JSON object!");
            Ok(DecompJSON {
                code: json_obj["code"].as_str().unwrap().to_string(),
                annotations: Vec::new(),
            })
        }
    }

    fn get_function_name_list(
        &self,
        r2p: &mut R2Pipe,
    ) -> Result<Vec<AFIJFunctionInfo>, r2pipe::Error> {
        info!("Getting function information from binary");
        let json = r2p.cmd("aflj");

        if let Ok(json_str) = json {
            let json_obj: Vec<AFIJFunctionInfo> =
                serde_json::from_str(json_str.as_ref()).expect("Unable to convert to JSON object!");
            Ok(json_obj)
        } else {
            Err(json.unwrap_err())
        }
    }

    fn get_basic_block_addresses(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<BasicBlockInfo, r2pipe::Error> {
        info!(
            "Getting the basic block information for function @ {}",
            function_addr
        );
        Self::go_to_address(r2p, function_addr);
        // Get basic block information
        let json = r2p.cmd("afbj");

        // Convert returned JSON into a BasicBlockInfo struct
        if let Ok(json_str) = json {
            let bb_addresses: BasicBlockInfo = serde_json::from_str(json_str.as_ref())
                .expect("Unable to convert returned object into a BasicBlockInfo struct!");
            Ok(bb_addresses)
        } else {
            Err(json.unwrap_err())
        }
    }

    fn get_local_variable_xref_details(&self, function_addr: u64, r2p: &mut R2Pipe) -> Result<LocalVariableXrefs, r2pipe::Error> {
        info!("Getting local variable xref details");
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("axvj").expect("axvj command failed");

        // Convert returned JSON into a BasicBlockInfo struct
        if let Ok(json_str) = json {
            let local_variable_xrefs: LocalVariableXrefs = serde_json::from_str(json_str.as_ref())
                .expect("Unable to convert returned object into a BasicBlockInfo struct!");
            Ok(local_variable_xrefs)
        } else {
            Err(json.unwrap_err())
        }
    }

    fn get_function_xref_details(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Vec<FunctionXrefDetails> {
        info!("Getting function xref details");
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("axffj").expect("axffj command failed");
        let mut json_obj: Vec<FunctionXrefDetails> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        debug!("Replacing all CALL xrefs with actual function name");
        // TODO: There is a minor bug in this where functions without any xrefs are included.
        // Been left in as may be useful later down the line.
        if !json_obj.is_empty() {
            debug!("Replacing all CALL xrefs with actual function name");
            for element in json_obj.iter_mut() {
                if element.type_field == "CALL" {
                    let function_name = r2p
                        .cmd(format!("afi. @ {}", &element.ref_field).as_str())
                        .expect("afi. command failed");
                    element.name = function_name;
                }
            }
        };
        json_obj
    }

    // Helper Functions
    fn write_to_json(&self, json_obj: &Value) {
        let mut fp_filename = self
            .file_path
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();

        fp_filename = fp_filename + "_" + &self.job_type_suffix.clone() + ".json";

        let mut output_filepath = PathBuf::new();
        output_filepath.push(self.output_path.clone());
        output_filepath.push(fp_filename);
        debug!("Save filename: {:?}", output_filepath);

        serde_json::to_writer(
            &File::create(&output_filepath).expect("Unable to create file!"),
            &json_obj,
        )
        .unwrap_or_else(|_| panic!("the world is ending: {:?}", output_filepath));
    }

    fn go_to_address(r2p: &mut R2Pipe, function_addr: u64) {
        r2p.cmd(format!("s @ {}", function_addr).as_str())
            .expect("failed to seek addr");
    }

    fn handle_symbols_pdb(&self, r2p: &mut R2Pipe) -> Result<(), Error> {
        // Download symbols if available
        debug!("Downloading pdb file for {:?}", self.file_path);
        let download_pdb = r2p.cmd("idpd");

        debug!("Download PDB Ret: {:?}", download_pdb);

        if download_pdb.unwrap().contains("success") {
            let ret = r2p.cmd("idp");
            debug!("Return value: {:?}", ret);

            Ok(())
        } else {
            Err(anyhow!("Unable to download pdb"))
        }
    }

    fn setup_r2_pipe(&self) -> R2Pipe {
        if self.r2p_config.use_curl_pdb {
            // Docs suggest this is unsafe
            env::set_var("R2_CURL", "1");
        }

        let opts = if self.r2p_config.debug {
            debug!("Creating r2 handle with debugging");
            R2PipeSpawnOptions {
                exepath: "radare2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=0"],
            }
        } else {
            debug!("Creating r2 handle without debugging");
            R2PipeSpawnOptions {
                exepath: "radare2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=1", "-2"],
            }
        };

        debug!("Attempting to create r2pipe using {:?}", self.file_path);
        let mut r2p = match R2Pipe::in_session() {
            Some(_) => R2Pipe::open().expect("Unable to open R2Pipe"),
            None => R2Pipe::spawn(self.file_path.to_str().unwrap(), Some(opts))
                .expect("Failed to spawn new R2Pipe"),
        };

        let info = r2p.cmdj("ij");
        if info.is_ok() {
            let info = info.unwrap();
            if info["bin"]["bintype"].as_str().unwrap() == "pe" {
                debug!("PE file found. Handling symbol download!");
                let ret = self.handle_symbols_pdb(&mut r2p);

                if ret.is_err() {
                    error!("Unable to get PDB info")
                }
            }
        }

        if self.r2p_config.extended_analysis {
            debug!(
                "Executing 'aaa' r2 command for {}",
                self.file_path.display()
            );
            r2p.cmd("aaa")
                .expect("Unable to complete standard analysis!");
            debug!("'aaa' r2 command complete for {}", self.file_path.display());
        } else {
            debug!("Executing 'aa' r2 command for {}", self.file_path.display());
            r2p.cmd("aa")
                .expect("Unable to complete standard analysis!");
            debug!(
                "'aa' r2 command complete for {:?}",
                self.file_path.display()
            );
        };
        r2p
    }
}
