use crate::afij::AFIJFunctionInfo;
use crate::agcj::AGCJFunctionCallGraph;
use crate::utils::sanitize_filename;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::Context;
use anyhow::Error;
use anyhow::Result;
use r2pipe::R2Pipe;
use r2pipe::R2PipeSpawnOptions;

use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_json;

use glob::glob;
use md5;
use serde_json::{json, Deserializer, Value};
use sha1;
use sha1::Digest as Sha1Digest;
use sha2::Digest as Sha2Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use std::string::String;
use std::sync::LazyLock;
use walkdir::WalkDir;

#[derive(PartialEq, Debug)]
pub enum PathType {
    Pattern,
    File,
    Dir,
    Unk,
}

#[derive(Debug, PartialEq, Clone, Copy, Hash, Eq)]
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

static JOB_TYPE_TO_SUFFIX: LazyLock<HashMap<ExtractionJobType, &'static str>> =
    LazyLock::new(|| {
        HashMap::from([
            (ExtractionJobType::BinInfo, "bininfo"),
            (ExtractionJobType::RegisterBehaviour, "reg"),
            (ExtractionJobType::FunctionXrefs, "func-xrefs"),
            (ExtractionJobType::CFG, "cfg"),
            (ExtractionJobType::CallGraphs, "cg"),
            (ExtractionJobType::FuncInfo, "finfo"),
            (ExtractionJobType::FunctionVariables, "fvars"),
            (ExtractionJobType::Decompilation, "decomp"),
            (ExtractionJobType::PCodeFunc, "pcode-func"),
            (ExtractionJobType::PCodeBB, "pcode-bb"),
            (ExtractionJobType::LocalVariableXrefs, "localvar-xrefs"),
            (ExtractionJobType::GlobalStrings, "strings"),
            (ExtractionJobType::FunctionBytes, "bytes"),
            (ExtractionJobType::FunctionZignatures, "zigs"),
        ])
    });

static SUFFIX_TO_JOB_TYPE: LazyLock<HashMap<&'static str, ExtractionJobType>> =
    LazyLock::new(|| {
        JOB_TYPE_TO_SUFFIX
            .iter()
            .map(|(job_type, suffix)| (*suffix, *job_type))
            .collect()
    });

#[derive(Debug)]
pub struct FileToBeProcessed {
    pub file_path: PathBuf,
    pub output_path: PathBuf,
    pub job_types: Vec<ExtractionJobType>,
    pub r2p_config: R2PipeConfig,
    pub with_annotations: bool,
    pub retry_aborted: bool,
    pub func_filename_template: String,
}

#[derive(Debug)]
pub struct FunctionToBeProcessed {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub ninstrs: u64,
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
    pub timeout: Option<u64>,
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
    pub v: Option<Vec<String>>,
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

impl
    From<(
        String,
        String,
        Vec<ExtractionJobType>,
        R2PipeConfig,
        bool,
        bool,
        String,
    )> for FileToBeProcessed
{
    fn from(
        orig: (
            String,
            String,
            Vec<ExtractionJobType>,
            R2PipeConfig,
            bool,
            bool,
            String,
        ),
    ) -> FileToBeProcessed {
        FileToBeProcessed {
            file_path: PathBuf::from(orig.0),
            output_path: PathBuf::from(orig.1),
            job_types: orig.2,
            r2p_config: orig.3,
            with_annotations: orig.4,
            retry_aborted: orig.5,
            func_filename_template: orig.6,
        }
    }
}

impl From<(String, u64, u64, u64)> for FunctionToBeProcessed {
    fn from(orig: (String, u64, u64, u64)) -> Self {
        FunctionToBeProcessed {
            name: orig.0,
            addr: orig.1,
            size: orig.2,
            ninstrs: orig.3,
        }
    }
}

impl From<AFIJFunctionInfo> for FunctionToBeProcessed {
    fn from(func_info: AFIJFunctionInfo) -> Self {
        FunctionToBeProcessed {
            name: func_info.name,
            addr: func_info.offset,
            size: func_info.size,
            ninstrs: func_info.ninstrs as u64,
        }
    }
}

impl From<AFLJFuncDetails> for FunctionToBeProcessed {
    fn from(func_details: AFLJFuncDetails) -> Self {
        FunctionToBeProcessed {
            name: func_details.name,
            addr: func_details.offset,
            size: func_details.size,
            ninstrs: func_details.ninstrs,
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

// Structs for ij - Information about the binary file
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ChecksumsEntry {
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
    pub baddr: Option<u64>,
    pub binsz: u64,
    pub bintype: String,
    pub bits: u16,
    pub canary: bool,
    pub injprot: bool,
    pub retguard: Option<bool>,
    pub class: String,
    #[serde(rename = "cmp.csum")]
    pub cmp_csum: Option<String>,
    pub compiled: String,
    pub compiler: String,
    pub crypto: bool,
    pub dbg_file: String,
    pub endian: String,
    pub havecode: bool,
    #[serde(rename = "hdr.csum")]
    pub hdr_csum: Option<String>,
    pub guid: String,
    pub intrp: String,
    pub laddr: u64,
    pub lang: Option<String>,
    pub linenum: bool,
    pub lsyms: bool,
    pub machine: String,
    pub nx: bool,
    pub os: String,
    pub overlay: Option<bool>,
    pub cc: String,
    pub pic: bool,
    pub relocs: bool,
    pub rpath: String,
    pub signed: Option<bool>,
    pub sanitize: bool,
    #[serde(rename = "static")]
    pub static_field: bool,
    pub stripped: bool,
    pub subsys: String,
    pub va: bool,
    pub checksums: HashMap<String, String>, // Always empty.
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub core: CoreEntry,
    pub bin: Option<BinEntry>, // Sometimes not provided within ij.
    pub checksums: Option<ChecksumsEntry>, // Populated manually with itj.
}

impl ExtractionJob {
    pub fn new(
        input_path: &PathBuf,
        output_path: &PathBuf,
        modes: &Vec<String>,
        debug: &bool,
        extended_analysis: &bool,
        use_curl_pdb: &bool,
        func_filename_template: &str,
        timeout: &Option<u64>,
        with_annotations: &bool,
        retry_aborted: &bool,
    ) -> Result<ExtractionJob, Error> {
        let mut job_types = vec![];
        let mut extraction_job_types = vec![];

        for mode in modes {
            let job_type = Self::extraction_job_matcher(mode)?;
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
            timeout: *timeout,
        };

        let p_type = Self::get_path_type(input_path);

        match p_type {
            PathType::File => {
                // For a single file, create one FileToBeProcessed object
                // but track all the job types
                let file = FileToBeProcessed {
                    file_path: input_path.to_owned(),
                    output_path: output_path.to_owned(),
                    job_types: extraction_job_types, // Use the vector of just ExtractionJobType
                    r2p_config: r2_handle_config,
                    with_annotations: *with_annotations,
                    retry_aborted: *retry_aborted,
                    func_filename_template: func_filename_template.to_string(),
                };

                Ok(ExtractionJob {
                    input_path: input_path.to_owned(),
                    input_path_type: p_type,
                    job_types,
                    files_to_be_processed: vec![file],
                    output_path: output_path.to_owned(),
                })
            }
            PathType::Dir | PathType::Pattern => {
                // Get file paths based on path type
                let files = match p_type {
                    PathType::Dir => ExtractionJob::get_file_paths_dir(input_path),
                    PathType::Pattern => {
                        let pattern = input_path.to_string_lossy();
                        ExtractionJob::get_file_paths_pattern(&pattern)
                    }
                    _ => unreachable!(),
                };

                // Create FileToBeProcessed objects for each file with all job types
                let files_to_be_processed = files
                    .into_iter()
                    .map(|f| FileToBeProcessed {
                        file_path: PathBuf::from(f),
                        output_path: output_path.to_owned(),
                        job_types: extraction_job_types.clone(),
                        r2p_config: r2_handle_config,
                        with_annotations: *with_annotations,
                        retry_aborted: *retry_aborted,
                        func_filename_template: func_filename_template.to_string(),
                    })
                    .collect();

                Ok(ExtractionJob {
                    input_path: input_path.to_owned(),
                    input_path_type: PathType::Dir, // For using parallel processing
                    job_types,
                    files_to_be_processed,
                    output_path: output_path.to_owned(),
                })
            }
            PathType::Unk => bail!("Failed to create ExtractionJob"),
        }
    }

    /// Get the type of the input path (file, directory, or pattern)
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

    /// Validate extraction modes and convert them to job types
    fn extraction_job_matcher(mode: &str) -> Result<ExtractionJobType, Error> {
        SUFFIX_TO_JOB_TYPE
            .get(mode)
            .copied()
            .ok_or_else(|| anyhow!("Incorrect command type - got {}", mode))
    }

    fn get_job_type_suffix(job_type: &ExtractionJobType) -> String {
        JOB_TYPE_TO_SUFFIX
            .get(job_type)
            .copied()
            .expect("Incorrect command type")
            .to_string()
    }

    fn get_output_extension(job_type: &ExtractionJobType) -> Option<&str> {
        match job_type {
            ExtractionJobType::FunctionBytes => None, // Output is a directory
            _ => Some("json"),
        }
    }

    /// Get all file paths in the input_path directory
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

    /// Get all file paths that match the pattern
    fn get_file_paths_pattern(pattern: &str) -> Vec<String> {
        let mut paths = Vec::new();
        for entry in glob(pattern)
            .expect("Failed to read glob pattern")
            .flatten()
        {
            if !entry.to_string_lossy().ends_with(".json") {
                paths.push(entry.to_string_lossy().to_string());
            }
        }
        paths
    }
}

impl FunctionToBeProcessed {
    fn write_to_bin(
        &self,
        r2p: &mut R2Pipe,
        output_dirpath: &PathBuf,
        filename_template: &str,
    ) -> Result<()> {
        let func_bytes = self.get_bytes(r2p)?;
        let output_filepath = self.get_output_filepath(output_dirpath, filename_template, "bin");
        std::fs::write(&output_filepath, func_bytes.bytes).with_context(|| {
            format!(
                "Failed to write function bytes to file: {:?}",
                output_filepath
            )
        })?;
        Ok(())
    }

    // Getters
    fn get_hex_address(&self) -> String {
        format!("{:x}", self.addr)
            .trim_start_matches("0x")
            .to_string()
    }

    fn get_output_filename(&self, template: &str, ext: &str) -> String {
        let mut func_filename = match template {
            "symbol" => self.name.clone(),
            "address" => self.get_hex_address(),
            _ => template
                .replace("{symbol}", &self.name)
                .replace("{address}", &self.get_hex_address())
                .replace("{ext}", ext),
        };

        func_filename = sanitize_filename(&func_filename);
        if ["symbol", "address"].contains(&template) {
            // Add an extension only if the user did not specify a custom template
            func_filename = func_filename + "." + ext;
        }
        func_filename
    }

    pub fn get_output_filepath(
        &self,
        output_dirpath: &PathBuf,
        filename_template: &str,
        ext: &str,
    ) -> PathBuf {
        let output_filename = self.get_output_filename(filename_template, ext);

        let mut output_filepath = PathBuf::new();
        output_filepath.push(output_dirpath);
        output_filepath.push(output_filename);
        output_filepath
    }

    fn get_bytes(&self, r2p: &mut R2Pipe) -> Result<FuncBytes, Error> {
        FileToBeProcessed::go_to_address(r2p, self.addr)?;
        let mut function_bytes = r2p.cmd(format!("p8 {}", self.size).as_str())?;
        function_bytes = function_bytes.trim().to_string();
        let decoded_bytes = hex::decode(&function_bytes).context("Failed to decode hex bytes")?;

        Ok(FuncBytes {
            bytes: decoded_bytes,
        })
    }

    fn get_basic_block_info(&self, r2p: &mut R2Pipe) -> Result<BasicBlockInfo, Error> {
        info!(
            "Getting the basic block information for function @ {}",
            self.addr
        );
        FileToBeProcessed::go_to_address(r2p, self.addr)?;

        let json = r2p.cmd("afbj").context("Command afbj failed")?;
        // Parse the JSON into a mutable serde_json::Value.
        let mut value: serde_json::Value = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;

        // Iterate over each object and convert "traced" from integer to boolean.
        if let Some(array) = value.as_array_mut() {
            for item in array.iter_mut() {
                if let Some(traced_value) = item.get_mut("traced") {
                    // If traced is a number, convert it to a bool.
                    if let Some(num) = traced_value.as_i64() {
                        *traced_value = serde_json::Value::Bool(num != 0);
                    }
                }
            }
        }

        // Deserialize JSON into a BasicBlockInfo struct
        let bb_info: BasicBlockInfo = serde_json::from_value(value.clone()).with_context(|| {
            format!(
                "Unable to convert {:?} into a BasicBlockInfo struct!",
                value
            )
        })?;
        Ok(bb_info)
    }

    fn get_local_variable_xref_details(
        &self,
        r2p: &mut R2Pipe,
    ) -> Result<LocalVariableXrefs, Error> {
        info!(
            "Getting local variable xref details for function @ {}",
            self.addr
        );
        FileToBeProcessed::go_to_address(r2p, self.addr)?;
        let json = r2p.cmd("axvj").context("Command axvj failed")?;

        let local_variable_xrefs: LocalVariableXrefs =
            serde_json::from_str(&json).with_context(|| {
                format!("Unable to convert {:?} to LocalVariableXrefs struct!", json)
            })?;
        Ok(local_variable_xrefs)
    }

    fn get_xref_details(&self, r2p: &mut R2Pipe) -> Result<Vec<FunctionXrefDetails>, Error> {
        info!("Getting xref details for function @ {}", self.addr);
        FileToBeProcessed::go_to_address(r2p, self.addr)?;
        let json = r2p.cmd("axffj").context("Command axffj failed")?;
        let mut json_obj: Vec<FunctionXrefDetails> =
            serde_json::from_str(&json).with_context(|| {
                format!(
                    "Unable to convert {:?} to FunctionXrefDetails struct!",
                    json
                )
            })?;

        // TODO: There is a minor bug in this where functions without any xrefs are included.
        // Been left in as may be useful later down the line.
        if !json_obj.is_empty() {
            debug!("Replacing all CALL xrefs with actual function name");
            for element in json_obj.iter_mut() {
                if element.type_field == "CALL" {
                    let cmd_str = format!("afi. @ {}", &element.ref_field);
                    let function_name = r2p.cmd(cmd_str.as_str()).context("Command afi. failed")?;
                    element.name = function_name.trim().to_string();
                }
            }
        };
        Ok(json_obj)
    }

    fn get_ghidra_decomp(
        &self,
        r2p: &mut R2Pipe,
        with_annotations: bool,
    ) -> Result<DecompJSON, Error> {
        FileToBeProcessed::go_to_address(r2p, self.addr)?;
        let json = r2p.cmd("pdgj").context("Command pdgj failed")?;

        if with_annotations {
            let json_obj: DecompJSON = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to DecompJSON struct!", json))?;
            Ok(json_obj)
        } else {
            let json_obj: Value = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            let parsed_code = json_obj["code"]
                .as_str()
                .with_context(|| format!("Unable to get code from {:?}!", json))?
                .to_string();
            let parsed_obj = DecompJSON {
                code: parsed_code,
                annotations: Vec::new(),
            };
            Ok(parsed_obj)
        }
    }
}

impl FileToBeProcessed {
    /// Returns the name of the input binary file
    fn get_file_name(&self) -> Result<String> {
        self.file_path
            .file_name()
            .ok_or_else(|| anyhow!("Unable to get file name from {:?}", self.file_path))
            .map(|os_str| os_str.to_string_lossy().to_string())
    }

    /// Returns the name of the output file for a given job type
    fn get_output_filename(&self, job_type_suffix: &str) -> Result<String> {
        let job_type = ExtractionJob::extraction_job_matcher(job_type_suffix)
            .context(format!("Incorrect job type suffix: {}", job_type_suffix))?;
        let ext = ExtractionJob::get_output_extension(&job_type);
        let ext_str = ext.map_or("".to_string(), |e| format!(".{}", e));
        let mut output_filename = self.get_file_name()?;

        if job_type == ExtractionJobType::Decompilation && self.with_annotations {
            output_filename = output_filename + "_" + job_type_suffix + "_annotations" + &ext_str;
        } else {
            output_filename = output_filename + "_" + job_type_suffix + &ext_str;
        };

        Ok(output_filename)
    }

    fn get_output_filepath(&self, job_type_suffix: &str) -> Result<PathBuf> {
        let output_filename = self.get_output_filename(job_type_suffix)?;
        let mut output_filepath = PathBuf::from(self.output_path.clone());
        output_filepath.push(output_filename);
        Ok(output_filepath)
    }

    fn get_tmp_output_filepath(&self, job_type_suffix: &str) -> Result<PathBuf> {
        let mut filepath_str = self
            .get_output_filepath(job_type_suffix)?
            .to_string_lossy()
            .to_string();
        filepath_str = filepath_str + ".part";
        let output_filepath = PathBuf::from(filepath_str.clone());
        Ok(output_filepath)
    }

    pub fn process_mode(&self, r2p: &mut R2Pipe, job_type: &ExtractionJobType) -> Result<()> {
        let job_type_suffix = ExtractionJob::get_job_type_suffix(job_type);

        // Prepare final output file path (could also be a directory)
        let output_path = self.get_output_filepath(&job_type_suffix)?;
        // Use temporary name to keep track of incomplete extraction
        let tmp_output_path = self.get_tmp_output_filepath(&job_type_suffix)?;

        match job_type {
            ExtractionJobType::BinInfo => self.extract_binary_info(r2p, &tmp_output_path),
            ExtractionJobType::RegisterBehaviour => {
                self.extract_register_behaviour(r2p, &tmp_output_path)
            }
            ExtractionJobType::FunctionXrefs => self.extract_function_xrefs(r2p, &tmp_output_path),
            ExtractionJobType::CFG => self.extract_func_cfgs(r2p, &tmp_output_path),
            ExtractionJobType::CallGraphs => {
                self.extract_function_call_graphs(r2p, &tmp_output_path)
            }
            ExtractionJobType::FuncInfo => self.extract_function_info(r2p, &tmp_output_path),
            ExtractionJobType::FunctionVariables => {
                self.extract_function_variables(r2p, &tmp_output_path)
            }
            ExtractionJobType::Decompilation => self.extract_decompilation(r2p, &tmp_output_path),
            ExtractionJobType::PCodeFunc => self.extract_pcode_function(r2p, &tmp_output_path),
            ExtractionJobType::PCodeBB => self.extract_pcode_basic_block(r2p, &tmp_output_path),
            ExtractionJobType::LocalVariableXrefs => {
                self.extract_local_variable_xrefs(r2p, &tmp_output_path)
            }
            ExtractionJobType::GlobalStrings => self.extract_global_strings(r2p, &tmp_output_path),
            ExtractionJobType::FunctionZignatures => {
                self.extract_function_zignatures(r2p, &tmp_output_path)
            }
            ExtractionJobType::FunctionBytes => self.extract_function_bytes(r2p, &tmp_output_path),
        }?;

        // Apply final output file name when extraction is done
        std::fs::rename(&tmp_output_path, &output_path).map_err(|e| {
            anyhow::anyhow!(
                "Failed to rename temporary path {:?}: {}",
                tmp_output_path,
                e
            )
        })?;
        Ok(())
    }

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
        let mut maybe_r2p: Option<R2Pipe> = None;

        // Process each job type with the same r2pipe instance
        for job_type in &self.job_types {
            info!("Processing job type: {:?}", job_type);

            // Check if the extracted data file already exists
            let job_type_suffix = ExtractionJob::get_job_type_suffix(job_type);
            let output_path = match self.get_output_filepath(&job_type_suffix) {
                Ok(path) => path,
                Err(e) => {
                    error!("Failed to get output filepath for {:?}: {}", job_type, e);
                    continue;
                }
            };
            let error_path = output_path.with_extension("error.log");

            if output_path.exists() {
                debug!(
                    "Skipping {:?} job for {:?}: already processed at {:?}.",
                    job_type_suffix, self.file_path, output_path
                );
                continue;
            } else if error_path.exists() && !self.retry_aborted {
                debug!(
                    "Skipping {:?} job for {:?}: already processed and failed. Error log at {:?}.",
                    job_type_suffix, self.file_path, error_path
                );
                continue;
            }

            // Lazily initialize r2p if not already done.
            let r2p = maybe_r2p.get_or_insert_with(|| {
                let mut pipe = self.setup_r2_pipe();
                self.analyse_r2_pipe(&mut pipe);
                pipe
            });

            match self.process_mode(r2p, job_type) {
                Ok(_) => debug!(
                    "Finished {:?} extraction job for {:?}: processed at {:?}.",
                    job_type_suffix, self.file_path, output_path
                ),
                Err(e) => {
                    error!(
                        "Aborted {:?} extraction job for {:?} due to error:\n{:?}\n\t> (stored in {:?}).",
                        job_type_suffix, self.file_path, e, error_path
                    );
                    std::fs::write(error_path, format!("{}", e)).unwrap();
                }
            }
        }

        // Close the r2pipe instance once after processing all job types
        if let Some(mut r2p) = maybe_r2p {
            r2p.close();
            info!("r2p closed after processing all job types");
        }
    }

    pub fn extract_binary_info(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Starting binary information extraction");
        let bininfo_json = r2p
            .cmd("ij")
            .with_context(|| "ij command failed to execute")?;
        let mut bininfo: BinaryInfo = serde_json::from_str(&bininfo_json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", bininfo_json))?;

        // Attempt to get checksums from r2pipe first
        let checksums = match r2p.cmd("itj") {
            Ok(checksums_json) => {
                debug!(
                    "Successfully got checksums JSON from itj: {}",
                    checksums_json
                );
                match serde_json::from_str::<ChecksumsEntry>(&checksums_json) {
                    Ok(cs) => {
                        // Check if all necessary checksums are present
                        if cs.md5.is_some() && cs.sha1.is_some() && cs.sha256.is_some() {
                            debug!("Using checksums from r2pipe (itj)");
                            Some(cs)
                        } else {
                            warn!("Checksums from r2pipe (itj) are incomplete.");
                            None
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse checksums JSON from r2pipe: {}.", e);
                        None
                    }
                }
            }
            Err(e) => {
                warn!("Failed to get checksums from r2pipe (itj): {}.", e);
                None
            }
        };

        // If checksums couldn't be obtained or were incomplete from r2pipe, calculate them manually
        bininfo.checksums = match checksums {
            Some(cs) => Some(cs),
            None => {
                // If None, we need to calculate the checksums manually
                info!("Falling back to manual checksum calculation in Rust");
                match self.get_checksums() {
                    Ok(manual_cs) => Some(manual_cs),
                    Err(e) => {
                        error!("Manual checksum calculation failed: {}", e);
                        None // Checksums couldn't be calculated at all
                    }
                }
            }
        };

        info!("Binary information and checksums extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(bininfo), output_path)?;
        Ok(())
    }

    pub fn extract_register_behaviour(
        &self,
        r2p: &mut R2Pipe,
        output_path: &PathBuf,
    ) -> Result<()> {
        let function_details = self.get_function_name_list(r2p)?;
        let mut register_behaviour_vec: HashMap<String, AEAFJRegisterBehaviour> = HashMap::new();
        info!("Executing aeafj for each function");
        for function in function_details.iter() {
            let seek_cmd = format!("s @ {}", &function.name);
            r2p.cmd(seek_cmd.as_str()).with_context(|| {
                format!("Command {:?} failed in {:?}.", seek_cmd, self.file_path)
            })?;
            let json = r2p.cmd("aeafj").with_context(|| {
                format!(
                    "Command aeafj failed in {:?} at function {:?}.",
                    self.file_path, function.name
                )
            })?;
            let json_obj: AEAFJRegisterBehaviour = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            register_behaviour_vec.insert(function.name.clone(), json_obj);
        }
        info!("All functions processed");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(register_behaviour_vec), output_path)?;
        Ok(())
    }

    pub fn extract_function_call_graphs(
        &self,
        r2p: &mut R2Pipe,
        output_path: &PathBuf,
    ) -> Result<()> {
        info!("Starting function call graph extraction");
        let json = r2p
            .cmd("agCj")
            .with_context(|| format!("agCj command failed to execute on {:?}", self.file_path))?;
        let function_call_graphs: Vec<AGCJFunctionCallGraph> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        info!("Function call graph extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_call_graphs), output_path)?;
        Ok(())
    }

    pub fn extract_function_info(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Starting function metdata extraction");
        let function_details: Vec<AFIJFunctionInfo> = self.get_function_name_list(r2p)?;

        info!("Writing extracted data to file");
        let json = json!(function_details);
        self.write_to_json(&json, output_path)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        Ok(())
    }

    pub fn extract_function_variables(
        &self,
        r2p: &mut R2Pipe,
        output_path: &PathBuf,
    ) -> Result<()> {
        info!("Starting function variables extraction");
        let function_details = self.get_function_name_list(r2p)?;
        let mut func_variables_vec: HashMap<String, AFVJFuncDetails> = HashMap::new();
        info!("Executing aeafj for each function");
        for function in function_details.iter() {
            let json = r2p
                .cmd(format!("afvj @ {}", &function.name).as_str())
                .with_context(|| {
                    format!(
                        "Command afvj failed in {:?} at function {:?}.",
                        self.file_path, function.name
                    )
                })?;
            let json_obj: AFVJFuncDetails = serde_json::from_str(&json)
                .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
            func_variables_vec.insert(function.name.clone(), json_obj);
        }
        info!("All functions processed");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(func_variables_vec), output_path)?;
        Ok(())
    }

    pub fn extract_func_cfgs(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Executing agfj @@f on {:?}", self.file_path);

        let json_raw = r2p.cmd("agfj @@f").with_context(|| {
            format!(
                "Failed to extract control flow graph information from {:?}.",
                self.file_path
            )
        })?;

        info!("Starting JSON fixup for {:?}", self.file_path);
        match self.fix_json_object(&json_raw) {
            Ok(json) => {
                info!("JSON fixup finished for {:?}", self.file_path);
                // If the cleaned JSON is an empty array, log an error and skip.
                if json == serde_json::Value::Array(vec![]) {
                    return Err(anyhow::anyhow!(
                        "File empty after JSON fixup - Only contains empty JSON array - {:?}",
                        self.file_path
                    ));
                } else {
                    self.write_to_json(&json, output_path)?;
                }
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Unable to parse json for {:?}: {}: {}",
                    self.file_path,
                    json_raw,
                    e
                ));
            }
        }
        Ok(())
    }

    pub fn extract_function_xrefs(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_xrefs: HashMap<String, Vec<FunctionXrefDetails>> = HashMap::new();

        info!("Extracting xrefs for each function");
        for function_info in function_details {
            let function = FunctionToBeProcessed::from(function_info);
            let ret = function.get_xref_details(r2p).with_context(|| {
                format!("Unable to get function xrefs from {:?}", self.file_path)
            })?;
            function_xrefs.insert(function.name.clone(), ret);
        }
        info!("All functions processed! Writing extracted data to file");
        self.write_to_json(&json!(function_xrefs), output_path)?;
        Ok(())
    }

    pub fn extract_decompilation(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Starting decompilation extraction!");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_decomp: HashMap<String, DecompJSON> = HashMap::new();

        for function_info in function_details {
            let function = FunctionToBeProcessed::from(function_info);
            let ret = function
                .get_ghidra_decomp(r2p, self.with_annotations)
                .with_context(|| {
                    format!(
                        "Unable to get decompilation for {:?} @ {:?}",
                        self.file_path, function.addr
                    )
                })?;
            function_decomp.insert(function.name.clone(), ret);
        }
        info!("Decompilation extracted successfully for all functions.");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_decomp), output_path)?;
        Ok(())
    }

    pub fn extract_pcode_function(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Starting pcode extraction at a function level");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_pcode = Vec::new();

        for function in function_details.iter() {
            let ret = self.get_ghidra_pcode(function.offset, function.ninstrs, r2p);

            let formatted_obj = PCodeJSONWithFuncName {
                function_name: function.name.clone(),
                pcode: ret.unwrap(),
            };

            function_pcode.push(formatted_obj);
        }
        info!("Pcode extracted successfully for all functions.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_pcode), output_path)?;
        Ok(())
    }

    pub fn extract_pcode_basic_block(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Starting pcode extraction for each basic block in each function within the binary");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_pcode = Vec::new();

        for function_info in function_details {
            let function = FunctionToBeProcessed::from(function_info);
            let bb_info = function.get_basic_block_info(r2p).with_context(|| {
                format!(
                    "Unable to get basic block addresses in {:?} @ {:?}",
                    self.file_path, function.addr
                )
            })?;
            let mut bb_pcode: Vec<PCodeJsonWithBB> = Vec::new();
            for bb in bb_info.iter() {
                let ret = self
                    .get_ghidra_pcode(bb.addr, bb.ninstr.try_into().unwrap(), r2p)
                    .with_context(|| {
                        format!(
                            "Basic block decompilation failed in {:?} at offset {:?}",
                            self.file_path, bb.addr
                        )
                    })?;
                let pcode_json = PCodeJsonWithBB {
                    block_start_adr: bb.addr,
                    pcode: ret.pcode,
                    asm: ret.asm,
                    bb_info: bb.clone(),
                };
                bb_pcode.push(pcode_json);
            }

            function_pcode.push(PCodeJsonWithBBAndFuncName {
                function_name: function.name.clone(),
                pcode_blocks: bb_pcode,
            });
        }
        info!("Pcode extracted successfully for all functions.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_pcode), output_path)?;
        Ok(())
    }

    pub fn extract_local_variable_xrefs(
        &self,
        r2p: &mut R2Pipe,
        output_path: &PathBuf,
    ) -> Result<()> {
        info!("Starting local variable xref extraction");
        let function_details = self.get_function_name_list(r2p)?;
        let mut function_local_variable_xrefs: HashMap<String, LocalVariableXrefs> = HashMap::new();

        for function_info in function_details {
            let function = FunctionToBeProcessed::from(function_info);
            let ret = function.get_local_variable_xref_details(r2p)?;
            function_local_variable_xrefs.insert(function.name.clone(), ret);
        }
        info!("Local variable xrefs extracted successfully for all functions.");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_local_variable_xrefs), output_path)?;
        Ok(())
    }

    pub fn extract_global_strings(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        info!("Starting Global String Extraction");
        let json = r2p
            .cmd("izj")
            .with_context(|| format!("Command izj failed in {:?}.", self.file_path))?;

        debug!("{}", json);
        let json_obj: Vec<StringEntry> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;

        self.write_to_json(&json!(json_obj), output_path)?;
        Ok(())
    }

    pub fn extract_function_zignatures(
        &self,
        r2p: &mut R2Pipe,
        output_path: &PathBuf,
    ) -> Result<()> {
        info!("Starting function zignatures extraction");
        let _ = r2p
            .cmd("zg")
            .with_context(|| format!("Command zg failed in {:?}.", self.file_path))?; // generate zignatures
        debug!("Finished generating function zignatures");
        let json = r2p
            .cmd("zj")
            .with_context(|| format!("Command zj failed in {:?}.", self.file_path))?;
        let function_zignatures: Vec<FunctionZignature> = serde_json::from_str(&json)
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        info!("Function zignatures extracted.");
        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_zignatures), output_path)?;
        Ok(())
    }

    pub fn extract_function_bytes(&self, r2p: &mut R2Pipe, output_dirpath: &PathBuf) -> Result<()> {
        info!("Starting function bytes extraction");
        let function_details = self.get_function_name_list(r2p)?;

        if !output_dirpath.is_dir() {
            std::fs::create_dir_all(&output_dirpath)
                .with_context(|| format!("Failed to create directory {:?}", output_dirpath))?;
        }

        for function_info in function_details {
            let function = FunctionToBeProcessed::from(function_info);
            debug!(
                "Function Name: {} Address: {} Size: {}",
                function.name, function.addr, function.size
            );
            function.write_to_bin(r2p, &output_dirpath, &self.func_filename_template)?;
        }
        info!("Function bytes successfully extracted");
        Ok(())
    }

    fn get_checksums(&self) -> Result<ChecksumsEntry, Error> {
        // Open the file for reading
        let file = File::open(&self.file_path)
            .with_context(|| format!("Failed to open file {:?}", self.file_path))?;

        // Create a buffered reader for efficient reading
        let mut reader = BufReader::new(file);

        // Initialize hashers
        let mut md5_hasher = md5::Context::new();
        let mut sha1_hasher = sha1::Sha1::new();
        let mut sha256_hasher = Sha256::new();

        // Use a reasonably sized buffer (64KB chunks)
        let mut buffer = [0; 65536];

        // Read the file in chunks and update all hashers
        loop {
            let bytes_read = reader
                .read(&mut buffer)
                .with_context(|| format!("Failed to read file {:?}", self.file_path))?;

            if bytes_read == 0 {
                // End of file
                break;
            }

            // Update all hashers with this chunk
            md5_hasher.consume(&buffer[..bytes_read]);
            Sha1Digest::update(&mut sha1_hasher, &buffer[..bytes_read]);
            Sha2Digest::update(&mut sha256_hasher, &buffer[..bytes_read]);
        }

        // Finalize all hashes
        let md5_result = format!("{:x}", md5_hasher.compute());
        let sha1_result = format!("{:x}", sha1_hasher.finalize());
        let sha256_result = format!("{:x}", sha256_hasher.finalize());

        // Return the results
        Ok(ChecksumsEntry {
            md5: Some(md5_result),
            sha1: Some(sha1_result),
            sha256: Some(sha256_result),
        })
    }

    // r2 commands to structs
    fn get_ghidra_pcode(
        &self,
        address: u64,
        num_instructons: u64,
        r2p: &mut R2Pipe,
    ) -> Result<PCodeJSON, Error> {
        Self::go_to_address(r2p, address)?;
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

    fn get_function_name_list(
        &self,
        r2p: &mut R2Pipe,
    ) -> Result<Vec<AFIJFunctionInfo>, anyhow::Error> {
        info!("Getting function information from binary");
        let json = r2p
            .cmd("aflj")
            .with_context(|| format!("Failed executing aflj on {:?}", self.file_path))?;

        let json_obj: Vec<AFIJFunctionInfo> = serde_json::from_str(json.as_ref())
            .with_context(|| format!("Unable to convert {:?} to JSON object!", json))?;
        Ok(json_obj)
    }

    // Helper Functions
    fn fix_json_object(&self, json_raw: &str) -> Result<serde_json::Value, serde_json::Error> {
        // Collect all JSON objects into a vector.
        let stream = Deserializer::from_str(json_raw).into_iter::<Value>();
        let json_objects: Result<Vec<Value>, _> = stream
            .filter_map(|result| {
                match result {
                    Ok(Value::Array(ref arr)) if arr.is_empty() => None, // skip empty arrays
                    other => Some(other),
                }
            })
            .collect();
        // Map the collected vector into a JSON array.
        json_objects.map(Value::Array)
    }

    fn write_to_json(&self, json_obj: &Value, output_filepath: &PathBuf) -> Result<()> {
        let file = File::create(&output_filepath)
            .with_context(|| format!("Unable to create file {:?}", output_filepath))?;
        serde_json::to_writer(&file, &json_obj)
            .with_context(|| format!("Failed to write JSON to {:?}", output_filepath))?;

        Ok(())
    }

    /// Seeks to the function address
    fn go_to_address(r2p: &mut R2Pipe, address: u64) -> Result<(), Error> {
        r2p.cmd(format!("s {}", address).as_str())
            .with_context(|| format!("Failed to seek address {:x}", address))?;
        Ok(())
    }

    /// Downloads the PDB file if available
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

        if let Some(timeout) = self.r2p_config.timeout {
            r2p.cmd(format!("e anal.timeout={}", timeout).as_str())
                .expect("Failed to set timeout");
        }

        if self.r2p_config.use_curl_pdb {
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
        }

        r2p
    }

    fn analyse_r2_pipe(&self, r2p: &mut R2Pipe) {
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
    }
}
