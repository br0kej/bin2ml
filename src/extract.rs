use crate::afij::AFIJFunctionInfo;
use crate::agcj::AGCJFunctionCallGraph;

use std::io;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Error;
use anyhow::Result;
use anyhow::Context;
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
use glob::glob;
use regex::Regex;

#[derive(PartialEq, Debug)]
pub enum PathType {
    Pattern,
    File,
    Dir,
    Unk,
}
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum ExtractionJobType {
    BinInfo, // Extract high level information from the binary (r2 ij)
    RegisterBehaviour,
    FunctionXrefs,
    CFG,
    CallGraphs,
    FuncInfo,
    FunctionVariables,
    Decompilation,
    PCodeFunc,
    PCodeBB,
    LocalVariableXrefs,
    GlobalStrings,
    FunctionBytes,
    FunctionZignatures,
}

#[derive(Debug)]
pub struct FileToBeProcessed {
    pub file_path: PathBuf,
    pub output_path: PathBuf,
    pub job_types: Vec<ExtractionJobType>,
    pub r2p_config: R2PipeConfig,
    pub with_annotations: bool,
}

#[derive(Debug)]
pub struct ExtractionJob {
    pub input_path: PathBuf,
    pub input_path_type: PathType,
    pub job_types: Vec<(ExtractionJobType, String)>,
    pub files_to_be_processed: Vec<FileToBeProcessed>,
    pub output_path: PathBuf,
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
            "bin_path: {:?} p_type: {:?} jobs: {:?}",
            self.input_path, self.input_path_type, self.job_types
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

impl From<(String, String, Vec<ExtractionJobType>, R2PipeConfig, bool)> for FileToBeProcessed {
    fn from(
        orig: (String, String, Vec<ExtractionJobType>, R2PipeConfig, bool),
    ) -> FileToBeProcessed {
        FileToBeProcessed {
            file_path: PathBuf::from(orig.0),
            output_path: PathBuf::from(orig.1),
            job_types: orig.2,
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

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJSONWithFuncName {
    pub function_name: String,
    pub pcode: PCodeJSON,
}

// Structs for pdgsd + basic block connectivity - Ghidra PCode JSON Output + afbj
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJsonWithBB {
    pub block_start_adr: u64,
    pub pcode: Vec<String>,
    pub asm: Option<Vec<String>>,
    pub bb_info: BasicBlockMetadataEntry,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PCodeJsonWithBBAndFuncName {
    pub function_name: String,
    pub pcode_blocks: Vec<PCodeJsonWithBB>,
}

// Structs for afbj - Basic Block JSON output
pub type BasicBlockInfo = Vec<BasicBlockMetadataEntry>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BasicBlockMetadataEntry {
    pub addr: u64,
    pub size: u64,
    pub jump: Option<u64>,
    pub fail: Option<u64>,
    pub opaddr: u64,
    pub inputs: u64,
    pub outputs: u64,
    pub ninstr: u64,
    pub instrs: Vec<u64>,
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

// Structs for afvj - Function Arguments, Registers, and Variables JSON output
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AFVJFuncDetails {
    pub reg: Vec<Regvar>,
    pub sp: Vec<Value>,
    pub bp: Vec<Bpvar>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StringEntry {
    pub vaddr: i64,
    pub paddr: i64,
    pub ordinal: i64,
    pub size: i64,
    pub length: i64,
    pub section: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub string: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FuncBytes {
    pub bytes: Vec<u8>,
}

// Structs for zj - Function signatures (called "zignatures" in r2)
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GraphEntry {
    pub cc: u64,
    pub nbbs: u64,
    pub edges: u64,
    pub ebbs: u64,
    pub bbsum: u64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VarEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub kind: char,
    pub delta: i64,
    pub isarg: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HashEntry {
    pub bbhash: String, // hexadecimal
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionZignature {
    pub name: String,
    pub bytes: String, // hexadecimal function bytes
    pub mask: String,  // hexadecimal
    pub graph: GraphEntry,
    pub addr: i64,
    pub next: Option<String>,
    pub types: String,
    pub refs: Vec<String>,
    pub xrefs: Vec<String>,
    pub collisions: Vec<String>, // colliding function names
    pub vars: Vec<VarEntry>,
    pub hash: HashEntry,
}

// Strcuts for ij - Information about the binary file
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumsEntry { // Output of itj
    md5: Option<String>,
    sha1: Option<String>,
    sha256: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CoreEntry {
    #[serde(rename = "type")]
    pub type_field: String,
    pub file: String,
    pub fd: i32,
    pub size: u64,
    pub humansz: String,
    pub iorw: bool,
    pub mode: String,
    pub block: u64,
    pub format: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinEntry {
    pub arch: String,
    pub baddr: u64,
    pub binsz: u64,
    pub bintype: String,
    pub bits: u16,
    pub canary: bool,
    pub injprot: bool,
    pub retguard: bool,
    pub class: String,
    #[serde(rename = "cmp.csum")]
    pub cmp_csum: String,
    pub compiled: String,
    pub compiler: String,
    pub crypto: bool,
    pub dbg_file: String,
    pub endian: String,
    pub havecode: bool,
    #[serde(rename = "hdr.csum")]
    pub hdr_csum: String,
    pub guid: String,
    pub intrp: String,
    pub laddr: u64,
    pub lang: String,
    pub linenum: bool,
    pub lsyms: bool,
    pub machine: String,
    pub nx: bool,
    pub os: String,
    pub overlay: bool,
    pub cc: String,
    pub pic: bool,
    pub relocs: bool,
    pub rpath: String,
    pub signed: bool,
    pub sanitize: bool,
    #[serde(rename = "static")]
    pub static_field: bool,
    pub stripped: bool,
    pub subsys: String,
    pub va: bool,
    pub checksums: ChecksumsEntry, // Always empty. Populating manually with itj
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub core: CoreEntry,
    pub bin: BinEntry,
}


impl ExtractionJob {
    pub fn new(
        input_path: &PathBuf,
        output_path: &PathBuf,
        modes: &Vec<String>,
        debug: &bool,
        extended_analysis: &bool,
        use_curl_pdb: &bool,
        with_annotations: &bool,
    ) -> Result<ExtractionJob, Error> {
        fn get_path_type(bin_path: &PathBuf) -> PathType {
            // Handle pattern first since it would raise NotFound error 
            let path_str = bin_path.to_string_lossy();
            if path_str.contains('*') || path_str.contains('?') || path_str.contains('[') {
                return PathType::Pattern;
            }

            let fpath_md = fs::metadata(bin_path).unwrap();
            if fpath_md.is_file() {
                PathType::File
            } else if fpath_md.is_dir() {
                PathType::Dir
            } else {
                PathType::Unk
            }
        }

        // This function is used to validate modes and convert them to job types
        fn extraction_job_matcher(mode: &str) -> Result<ExtractionJobType, Error> {
            match mode {
                "bininfo" => Ok(ExtractionJobType::BinInfo),
                "finfo" => Ok(ExtractionJobType::FuncInfo),
                "fvars" => Ok(ExtractionJobType::FunctionVariables),
                "reg" => Ok(ExtractionJobType::RegisterBehaviour),
                "cfg" => Ok(ExtractionJobType::CFG),
                "func-xrefs" => Ok(ExtractionJobType::FunctionXrefs),
                "cg" => Ok(ExtractionJobType::CallGraphs),
                "decomp" => Ok(ExtractionJobType::Decompilation),
                "pcode-func" => Ok(ExtractionJobType::PCodeFunc),
                "pcode-bb" => Ok(ExtractionJobType::PCodeBB),
                "localvar-xrefs" => Ok(ExtractionJobType::LocalVariableXrefs),
                "strings" => Ok(ExtractionJobType::GlobalStrings),
                "bytes" => Ok(ExtractionJobType::FunctionBytes),
                "zigs" => Ok(ExtractionJobType::FunctionZignatures),
                _ => bail!("Incorrect command type - got {}", mode),
            }
        }

        let mut job_types = vec![];
        let mut extraction_job_types = vec![];

        for mode in modes {
            let job_type = extraction_job_matcher(mode)?;
            job_types.push((job_type, mode.clone()));
            extraction_job_types.push(job_type); // Store just the job type

            if job_type != ExtractionJobType::Decompilation && *with_annotations {
                warn!(
                    "Annotations are only supported for decompilation extraction (mode: {})",
                    mode
                );
            }
        }

        let r2_handle_config = R2PipeConfig {
            debug: *debug,
            extended_analysis: *extended_analysis,
            use_curl_pdb: *use_curl_pdb,
        };

        let p_type = get_path_type(input_path);

        if p_type == PathType::File {
            // For a single file, create one FileToBeProcessed object
            // but track all the job types
            let file = FileToBeProcessed {
                file_path: input_path.to_owned(),
                output_path: output_path.to_owned(),
                job_types: extraction_job_types, // Use the vector of just ExtractionJobType
                r2p_config: r2_handle_config,
                with_annotations: *with_annotations,
            };

            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: p_type,
                job_types,
                files_to_be_processed: vec![file],
                output_path: output_path.to_owned(),
            })
        } else if p_type == PathType::Dir {
            // For a directory, get all file paths
            let files = ExtractionJob::get_file_paths_dir(input_path);

            // Create FileToBeProcessed objects for each file with all job types
            let files_to_be_processed = files
                .into_iter()
                .map(|f| FileToBeProcessed {
                    file_path: PathBuf::from(f),
                    output_path: output_path.to_owned(),
                    job_types: extraction_job_types.clone(),
                    r2p_config: r2_handle_config,
                    with_annotations: *with_annotations,
                })
                .collect();

            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: p_type,
                job_types,
                files_to_be_processed,
                output_path: output_path.to_owned(),
            })
        } else if p_type == PathType::Pattern {
            // For a match pattern get the list of matching file paths
            let pattern = input_path.to_string_lossy();
            let files = ExtractionJob::get_file_paths_pattern(&pattern);

            // Create FileToBeProcessed objects for each file with all job types
            let files_to_be_processed = files
                .into_iter()
                .map(|f| FileToBeProcessed {
                    file_path: PathBuf::from(f),
                    output_path: output_path.to_owned(),
                    job_types: extraction_job_types.clone(),
                    r2p_config: r2_handle_config,
                    with_annotations: *with_annotations,
                })
                .collect();

            Ok(ExtractionJob {
                input_path: input_path.to_owned(),
                input_path_type: PathType::Dir, // For using parallel processing
                job_types,
                files_to_be_processed,
                output_path: output_path.to_owned(),
            })
        } else {
            bail!("Failed to create ExtractionJob")
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

    fn get_file_paths_pattern(pattern: &str) -> Vec<String> {
        let mut paths = Vec::new();
        // glob returns an iterator over Result<PathBuf, GlobError>
        for entry in glob(pattern).expect("Failed to read glob pattern") {
            if let Ok(path) = entry {
                if path.is_file() {
                    // Exclude JSON files
                    if let Some(fname) = path.file_name() {
                        if !fname.to_string_lossy().ends_with(".json") {
                            paths.push(path.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }
        paths
    }
}

impl FileToBeProcessed {
    pub fn process_all_modes(&self) {
        info!(
            "Starting extraction for {} job types on {:?}",
            self.job_types.len(),
            self.file_path
        );

        // Skip processing if no job types
        if self.job_types.is_empty() {
            info!("No job types to process for {:?}", self.file_path);
            return;
        }

        // Set up a single r2pipe instance
        let mut r2p = self.setup_r2_pipe();

        // Process each job type with the same r2pipe instance
        for job_type in &self.job_types {
            info!("Processing job type: {:?}", job_type);

            let job_type_suffix = self.get_job_type_suffix(job_type);

            match job_type {
                ExtractionJobType::BinInfo => {
                    self.extract_binary_info(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::RegisterBehaviour => {
                    self.extract_register_behaviour(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::FunctionXrefs => {
                    self.extract_function_xrefs(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::CFG => self.extract_func_cfgs(&mut r2p, job_type_suffix),
                ExtractionJobType::CallGraphs => {
                    self.extract_function_call_graphs(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::FuncInfo => {
                    self.extract_function_info(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::FunctionVariables => {
                    self.extract_function_variables(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::Decompilation => {
                    self.extract_decompilation(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::PCodeFunc => {
                    self.extract_pcode_function(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::PCodeBB => {
                    self.extract_pcode_basic_block(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::LocalVariableXrefs => {
                    self.extract_local_variable_xrefs(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::GlobalStrings => {
                    self.extract_global_strings(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::FunctionZignatures => {
                    self.extract_function_zignatures(&mut r2p, job_type_suffix)
                }
                ExtractionJobType::FunctionBytes => {
                    self.extract_function_bytes(&mut r2p, job_type_suffix)
                }
            }
        }

        // Close the r2pipe instance once after processing all job types
        r2p.close();
        info!("r2p closed after processing all job types");
    }

    pub fn get_job_type_suffix(&self, job_type: &ExtractionJobType) -> String {
        match job_type {
            ExtractionJobType::BinInfo => "bininfo",
            ExtractionJobType::RegisterBehaviour => "reg",
            ExtractionJobType::FunctionXrefs => "func-xrefs",
            ExtractionJobType::CFG => "cfg",
            ExtractionJobType::CallGraphs => "cg",
            ExtractionJobType::FuncInfo => "finfo",
            ExtractionJobType::FunctionVariables => "fvars",
            ExtractionJobType::Decompilation => "decomp",
            ExtractionJobType::PCodeFunc => "pcode-func",
            ExtractionJobType::PCodeBB => "pcode-bb",
            ExtractionJobType::LocalVariableXrefs => "localvar-xrefs",
            ExtractionJobType::GlobalStrings => "strings",
            ExtractionJobType::FunctionZignatures => "zigs",
            ExtractionJobType::FunctionBytes => "bytes",
        }
        .to_string()
    }

    pub fn data_extracter_single(&self, job_type: &ExtractionJobType) {
        info!("Starting extraction for {:?}", job_type);
        let mut r2p = self.setup_r2_pipe();

        let job_type_suffix = self.get_job_type_suffix(job_type);

        match job_type {
            ExtractionJobType::BinInfo => {
                self.extract_binary_info(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::RegisterBehaviour => {
                self.extract_register_behaviour(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::FunctionXrefs => {
                self.extract_function_xrefs(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::CFG => self.extract_func_cfgs(&mut r2p, job_type_suffix),
            ExtractionJobType::CallGraphs => {
                self.extract_function_call_graphs(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::FuncInfo => self.extract_function_info(&mut r2p, job_type_suffix),
            ExtractionJobType::FunctionVariables => self.extract_function_variables(&mut r2p, job_type_suffix),
            ExtractionJobType::Decompilation => {
                self.extract_decompilation(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::PCodeFunc => self.extract_pcode_function(&mut r2p, job_type_suffix),
            ExtractionJobType::PCodeBB => self.extract_pcode_basic_block(&mut r2p, job_type_suffix),
            ExtractionJobType::LocalVariableXrefs => {
                self.extract_local_variable_xrefs(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::GlobalStrings => {
                self.extract_global_strings(&mut r2p, job_type_suffix)
            }
            ExtractionJobType::FunctionZignatures => {
                self.extract_function_zignatures(&mut r2p, job_type_suffix)
            },
            ExtractionJobType::FunctionBytes => {
                self.extract_function_bytes(&mut r2p, job_type_suffix)
            }
        }

        r2p.close();
        info!("r2p closed");
    }

    pub fn extract_binary_info(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting binary information extraction");
        let bininfo_json = r2p.cmd("ij")
            .expect("ij command failed to execute.");
        let mut bininfo: BinaryInfo = serde_json::from_str(&bininfo_json)
            .expect(&format!("Unable to convert ij string to JSON object: `{}`", bininfo_json));

        let checksums_json = r2p.cmd("itj")
            .expect("itj command failed to execute.");
        let checksums: ChecksumsEntry = serde_json::from_str(&checksums_json)
            .expect(&format!("Unable to convert itj string to JSON object: `{}`", checksums_json));

        bininfo.bin.checksums = checksums;

        info!("Binary information extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(bininfo), job_type_suffix)
    }

    pub fn extract_register_behaviour(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        let function_details = self.get_function_name_list(r2p);
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
            info!("Writing extracted data to file");
            self.write_to_json(&json!(register_behaviour_vec), job_type_suffix)
        } else {
            error!(
                "Failed to extract function details to generate register behaviour - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_function_call_graphs(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting function call graph extraction");
        let json = r2p.cmd("agCj").expect("agCj command failed to execute");
        let function_call_graphs: Vec<AGCJFunctionCallGraph> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        info!("Function call graph extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_call_graphs), job_type_suffix)
    }

    pub fn extract_function_info(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting function metdata extraction");
        let mut fp_filename = self
            .file_path
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();

        fp_filename = fp_filename + "_" + &job_type_suffix;
        let f_name = format!("{:?}/{}.json", self.output_path, fp_filename);
        if !Path::new(&f_name).exists() {
            let function_details: Result<Vec<AFIJFunctionInfo>, r2pipe::Error> =
                self.get_function_name_list(r2p);

            if function_details.is_err() {
                error!("Unable to extract function info for {:?}", self.file_path);
            } else {
                info!("Writing extracted data to file");
                self.write_to_json(&json!(function_details.unwrap()), job_type_suffix)
            }
        } else {
            info!("{} already exists. Skipping", f_name);
        }
    }

    pub fn extract_function_variables(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        let function_details = self.get_function_name_list(r2p);
        if function_details.is_ok() {
            let mut func_variables_vec: HashMap<String, AFVJFuncDetails> =
                HashMap::new();
            info!("Executing aeafj for each function");
            for function in function_details.unwrap().iter() {
                let json = r2p.cmd(format!("afvj @ {}", &function.name).as_str())
                    .expect("Command failed.");
                let json_obj: AFVJFuncDetails =
                    serde_json::from_str(&json).expect("Unable to convert to JSON object!");
                func_variables_vec.insert(function.name.clone(), json_obj);
            }
            info!("All functions processed");
            info!("Writing extracted data to file");
            self.write_to_json(&json!(func_variables_vec), job_type_suffix)
        } else {
            error!(
                "Failed to extract function variable details - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_func_cfgs(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        let mut fp_filename = Path::new(&self.file_path)
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();
        fp_filename = format!("{}_{}", fp_filename, job_type_suffix);
        let f_name = format!("{:?}/{}.json", &self.output_path, fp_filename);

        if !Path::new(&f_name).exists() {
            info!("{} not found. Continuing processing.", f_name);
            info!("Executing agfj @@f on {:?}", self.file_path);

            let json_raw = r2p
                .cmd("agfj @@f")
                .expect("Failed to extract control flow graph information.");

            info!("Starting JSON fixup for {:?}", self.file_path);
            match self.fix_json_object(&json_raw) {
                Ok(json) => {
                    info!("JSON fixup finished for {:?}", self.file_path);
                    // If the cleaned JSON is an empty array, log an error and skip.
                    if json == serde_json::Value::Array(vec![]) {
                        error!(
                            "File empty after JSON fixup - Only contains empty JSON array - {}",
                            f_name
                        );
                    } else {
                        self.write_to_json(&json, job_type_suffix);
                    }
                }
                Err(e) => {
                    error!(
                        "Unable to parse json for {}: {}: {}",
                        fp_filename, json_raw, e
                    );
                    // Here, you can choose to return, skip the operation, or take other action.
                }
            }
        } else {
            info!("{} already exists. Skipping", f_name);
        }
    }

    pub fn extract_function_xrefs(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        let function_details = self.get_function_name_list(r2p);
        let mut function_xrefs: HashMap<String, Vec<FunctionXrefDetails>> = HashMap::new();
        info!("Extracting xrefs for each function");
        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_function_xref_details(function.offset, r2p);
                function_xrefs.insert(function.name.clone(), ret);
            }
            info!("All functions processed");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_xrefs), job_type_suffix)
        } else {
            error!(
                "Failed to extract function xrefs - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_decompilation(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting decompilation extraction!");
        let function_details = self.get_function_name_list(r2p);
        let mut function_decomp: HashMap<String, DecompJSON> = HashMap::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_ghidra_decomp(function.offset, r2p);
                function_decomp.insert(function.name.clone(), ret.unwrap());
            }
            info!("Decompilation extracted successfully for all functions.");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_decomp), job_type_suffix)
        } else {
            error!(
                "Failed to extract function decompilation - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_pcode_function(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting pcode extraction at a function level");
        let function_details = self.get_function_name_list(r2p);
        let mut function_pcode = Vec::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_ghidra_pcode_function(function.offset, function.ninstrs, r2p);

                let formatted_obj = PCodeJSONWithFuncName {
                    function_name: function.name.clone(),
                    pcode: ret.unwrap(),
                };

                function_pcode.push(formatted_obj);
            }
            info!("Pcode extracted successfully for all functions.");
            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_pcode), job_type_suffix)
        } else {
            error!(
                "Failed to extract function decompilation - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_pcode_basic_block(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting pcode extraction for each basic block in each function within the binary");
        let function_details = self.get_function_name_list(r2p);
        let mut function_pcode = Vec::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let bb_addresses = self.get_basic_block_addresses(function.offset, r2p);
                let mut bb_pcode: Vec<PCodeJsonWithBB> = Vec::new();
                for bb in bb_addresses.unwrap().iter() {
                    let ret =
                        self.get_ghidra_pcode_function(bb.addr, bb.ninstr.try_into().unwrap(), r2p);
                    if ret.is_ok() {
                        let ret = ret.unwrap();
                        let pcode_json = PCodeJsonWithBB {
                            block_start_adr: bb.addr,
                            pcode: ret.pcode,
                            asm: ret.asm,
                            bb_info: bb.clone(),
                        };
                        bb_pcode.push(pcode_json);
                    }
                }

                function_pcode.push(PCodeJsonWithBBAndFuncName {
                    function_name: function.name.clone(),
                    pcode_blocks: bb_pcode,
                });
            }
            info!("Pcode extracted successfully for all functions.");
            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_pcode), job_type_suffix)
        } else {
            error!(
                "Failed to extract function pcode - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_local_variable_xrefs(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting local variable xref extraction");
        let function_details = self.get_function_name_list(r2p);
        let mut function_local_variable_xrefs: HashMap<String, LocalVariableXrefs> = HashMap::new();

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                let ret = self.get_local_variable_xref_details(function.offset, r2p);
                function_local_variable_xrefs.insert(function.name.clone(), ret.unwrap());
            }
            info!("Local variable xrefs extracted successfully for all functions.");

            info!("Writing extracted data to file");
            self.write_to_json(&json!(function_local_variable_xrefs), job_type_suffix)
        } else {
            error!(
                "Failed to extract local variable xrefs - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    pub fn extract_global_strings(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting Global String Extraction");
        let json = r2p.cmd("izj");

        if json.is_ok() {
            let json = json.unwrap();
            debug!("{}", json);
            let json_obj: Vec<StringEntry> =
                serde_json::from_str(&json).expect("Unable to convert to JSON object!");

            self.write_to_json(&json!(json_obj), job_type_suffix)
        } else {
            error!("Failed to execute izj command successfully")
        }
    }

    pub fn extract_function_zignatures(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting function zignatures extraction");
        let _ = r2p.cmd("zg"); // generate zignatures
        debug!("Finished generating function zignatures");
        let json = r2p.cmd("zj").expect("zj command failed to execute");
        let function_zignatures: Vec<FunctionZignature> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        info!("Function zignatures extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_zignatures), job_type_suffix)
    }

    pub fn extract_function_bytes(&self, r2p: &mut R2Pipe, job_type_suffix: String) {
        info!("Starting function bytes extraction");
        let function_details = self.get_function_name_list(r2p);

        if function_details.is_ok() {
            for function in function_details.unwrap().iter() {
                debug!(
                    "Function Name: {} Offset: {} Size: {}",
                    function.name, function.offset, function.size
                );
                let function_bytes = self.get_bytes_function(function.offset, function.size, r2p);
                if let Ok(valid_bytes_obj) = function_bytes {
                    Self::write_to_bin(self, &function.name, &valid_bytes_obj.bytes, &job_type_suffix)
                        .expect("Failed to write bytes to bin.");
                };
            }
            info!("Function bytes successfully extracted");
        } else {
            error!(
                "Failed to extract function bytes - Error in r2 extraction for {:?}",
                self.file_path
            )
        }
    }

    // r2 commands to structs
    fn get_bytes_function(
        &self,
        function_addr: u64,
        function_size: i128,
        r2p: &mut R2Pipe,
    ) -> Result<FuncBytes, r2pipe::Error> {
        Self::go_to_address(r2p, function_addr);
        r2p.cmd(format!("s {}", function_addr).as_str())?;
        let function_bytes = r2p.cmd(format!("p8 {}", function_size).as_str())?;
        let function_bytes = function_bytes.trim();
        let function_bytes = hex::decode(function_bytes).map_err(|e| {
            r2pipe::Error::Io(io::Error::new(io::ErrorKind::InvalidData, 
                format!("Hex decode error: {}", e)))
        })?;

        Ok(FuncBytes {
            bytes: function_bytes,
        })
    }

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

    fn get_local_variable_xref_details(
        &self,
        function_addr: u64,
        r2p: &mut R2Pipe,
    ) -> Result<LocalVariableXrefs, r2pipe::Error> {
        info!("Getting local variable xref details");
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("axvj");

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
    fn fix_json_object(
        &self, 
        json_raw: &String
    ) -> Result<serde_json::Value, serde_json::Error> {
        let mut json_str = json_raw.replace("[]\n", ",");
        json_str = json_str.replace("}]\n[{", "}],\n[{");
        json_str.insert(0, '[');
        json_str.push(']');
        json_str = json_str.replace("}]\n,]", "}]\n]");
        json_str = json_str.replace("\n,,[{", "\n,[{");
        json_str = json_str.replace("\n,,[{", "\n,[{");

        if json_str == "[,]" {
            // No valid results were found, so return an empty JSON array.
            return Ok(Value::Array(vec![]));
        }

        // Attempt to parse the JSON. Any parsing error will be returned.
        let json: Value = serde_json::from_str(&json_str)?;
        Ok(json)
    }

    fn write_to_json(&self, json_obj: &Value, job_type_suffix: String) {
        let mut fp_filename = self
            .file_path
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();

        fp_filename = if self.with_annotations {
            fp_filename + "_" + &job_type_suffix + "_annotations" + ".json"
        } else {
            fp_filename + "_" + &job_type_suffix + ".json"
        };

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

    fn sanitize_function_name(&self, original: &str) -> String {
        // Replace non-valid characters with '_'
        // Valid characters: letters, digits, '_', '-', and '.'
        let re = Regex::new(r"[^\w.-]").unwrap();
        re.replace_all(original, "_").into_owned()
    }

    fn write_to_bin(
        &self, 
        function_name: &String, 
        func_bytes: &[u8],
        dirname_suffix: &String,
    ) -> Result<()> {
        // Extract the file stem from self.file_path and add context if missing.
        let file_stem = self.file_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("Unable to get filename from {:?}", self.file_path))?
            .to_string_lossy()
            .to_string();

        // Construct the full output directory path.
        let mut output_dir = self.output_path.clone();
        // Build the directory name by combining the file stem with the given suffix.
        let dir_name = format!("{}_{}", file_stem, dirname_suffix);
        output_dir.push(&dir_name);
        fs::create_dir_all(&output_dir)
            .with_context(|| format!("Failed to create directory {:?}", output_dir))?;
        
        // Construct the full output file path.
        let mut output_filepath = output_dir.clone();
        // Sanitize the function name to create a valid filename.
        let sanitized_function_name = self.sanitize_function_name(function_name);
        let file_name = format!("{}.bin", sanitized_function_name);
        output_filepath.push(file_name);

        // Check if a file with same name the sanitized name already exists.
        if output_filepath.exists() {
            debug!(
                "Duplicate function binary file detected for '{}' at {:?}. Skipping.",
                function_name,
                output_filepath
            );
            return Ok(());
        }

        // Write the file and attach context on error.
        fs::write(&output_dir, func_bytes)
            .with_context(|| format!("Failed to write file {:?}", output_dir))?;

        Ok(())
    }

    fn go_to_address(r2p: &mut R2Pipe, function_addr: u64) {
        r2p.cmd(format!("s {}", function_addr).as_str())
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
                args: vec!["-e bin.cache=true", "-e log.level=0", "-e asm.pseudo=true"],
            }
        } else {
            debug!("Creating r2 handle without debugging");
            R2PipeSpawnOptions {
                exepath: "radare2".to_owned(),
                args: vec![
                    "-e bin.cache=true",
                    "-e log.level=1",
                    "-2",
                    "-e asm.pseudo=true",
                ],
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
