use crate::afij::AFIJFunctionInfo;
use crate::agcj::AGCJFunctionCallGraph;
use crate::agfj::AGFJFunc;
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
use serde::ser::{SerializeSeq, Serializer};
use serde_json::{json, value::RawValue, Deserializer, Value};
use sha1;
use sha1::Digest as Sha1Digest;
use sha2::Digest as Sha2Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read};
use std::path::PathBuf;
use std::string::String;
use std::sync::LazyLock;
use once_cell::sync::OnceCell;
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
    FunctionCFG, // Like CFG, but in a separate file for each function
    CallGraphs,
    FuncInfo,
    FunctionVariables,
    Decompilation,
    PCodeFunc,
    PCodeBB,
    LocalVariableXrefs,
    GlobalStrings,
    FunctionBytes,
    FunctionBytesMasked,
    FunctionZignatures,
}

static JOB_TYPE_TO_SUFFIX: LazyLock<HashMap<ExtractionJobType, &'static str>> =
    LazyLock::new(|| {
        HashMap::from([
            (ExtractionJobType::BinInfo, "bininfo"),
            (ExtractionJobType::RegisterBehaviour, "reg"),
            (ExtractionJobType::FunctionXrefs, "func-xrefs"),
            (ExtractionJobType::CFG, "cfg"),
            (ExtractionJobType::FunctionCFG, "func-cfg"),
            (ExtractionJobType::CallGraphs, "cg"),
            (ExtractionJobType::FuncInfo, "finfo"),
            (ExtractionJobType::FunctionVariables, "fvars"),
            (ExtractionJobType::Decompilation, "decomp"),
            (ExtractionJobType::PCodeFunc, "pcode-func"),
            (ExtractionJobType::PCodeBB, "pcode-bb"),
            (ExtractionJobType::LocalVariableXrefs, "localvar-xrefs"),
            (ExtractionJobType::GlobalStrings, "strings"),
            (ExtractionJobType::FunctionBytes, "bytes"),
            (ExtractionJobType::FunctionBytesMasked, "bytes-masked"),
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
    pub function_list: OnceCell<Vec<FunctionToBeProcessed>>,
}

#[derive(Debug, Clone)]
pub struct FunctionToBeProcessed {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub ninstrs: u64,
    pub nblocks: u64,
}

#[derive(Debug)]
pub struct ExtractionJob {
    pub input_path: PathBuf,
    pub input_path_type: PathType,
    pub job_types: Vec<(ExtractionJobType, String)>,
    pub files_to_be_processed: Vec<FileToBeProcessed>,
    pub output_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct R2PipeConfig {
    pub debug: bool,
    pub analysis_mode: String,
    pub use_curl_pdb: bool,
    pub apply_relocations: bool,
    pub disable_pseudo_asm: bool,
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
    #[serde(alias = "addr")]
    pub offset: u64,
    pub name: String,
    pub size: u64,
    #[serde(rename = "is-pure")]
    pub is_pure: String,
    pub realsz: u64,
    pub noreturn: bool,
    #[serde(default)]
    pub recursive: bool,
    pub stackframe: u64,
    pub calltype: String,
    pub cost: u64,
    pub cc: u64,
    pub bits: u64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub nbbs: u64,
    #[serde(default)]
    pub tracecov: u64,
    #[serde(rename = "is-lineal")]
    pub is_lineal: bool,
    pub ninstrs: u64,
    pub edges: u64,
    pub ebbs: u64,
    #[serde(default)]
    pub signature: String,
    #[serde(alias = "minaddr")]
    pub minbound: i64,
    #[serde(alias = "maxaddr")]
    pub maxbound: u64,
    #[serde(default)]
    pub maxbbins: Option<u64>,
    #[serde(default)]
    pub midbbins: Option<f64>,
    #[serde(default)]
    pub ratbbins: Option<f64>,
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
            function_list: OnceCell::new(),
        }
    }
}

impl From<(String, u64, u64, u64, u64)> for FunctionToBeProcessed {
    fn from(orig: (String, u64, u64, u64, u64)) -> Self {
        FunctionToBeProcessed {
            name: orig.0,
            addr: orig.1,
            size: orig.2,
            ninstrs: orig.3,
            nblocks: orig.4,
        }
    }
}

impl From<AFIJFunctionInfo> for FunctionToBeProcessed {
    fn from(func_info: AFIJFunctionInfo) -> Self {
        FunctionToBeProcessed {
            name: func_info.name,
            addr: func_info.offset,
            size: func_info.size,
            ninstrs: func_info.ninstrs,
            nblocks: func_info.nbbs,
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
            nblocks: func_details.nbbs,
        }
    }
}

impl From<AGFJFunc> for FunctionToBeProcessed {
    fn from(func: AGFJFunc) -> Self {
        FunctionToBeProcessed {
            name: func.name,
            addr: func.offset,
            size: func.size,
            ninstrs: func.ninstr,
            nblocks: func.blocks.len() as u64,
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

// Custom deserializer for converting integer (0 or 1) to boolean
fn deserialize_bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let num = i64::deserialize(deserializer)?;
    Ok(num != 0) // 0 is false, anything else is true
}

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
    #[serde(deserialize_with = "deserialize_bool_from_int")]
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
    pub mask: Option<Vec<u8>>,
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
        analysis_mode: &str,
        use_curl_pdb: &bool,
        apply_relocations: &bool,
        disable_pseudo_asm: &bool,
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
            analysis_mode: analysis_mode.to_string(),
            apply_relocations: *apply_relocations,
            disable_pseudo_asm: *disable_pseudo_asm,
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
                    function_list: OnceCell::new(),
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
                        r2p_config: r2_handle_config.clone(),
                        with_annotations: *with_annotations,
                        retry_aborted: *retry_aborted,
                        func_filename_template: func_filename_template.to_string(),
                        function_list: OnceCell::new(),
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
            // Add here if output is not a JSON file (None if a directory)
            ExtractionJobType::FunctionBytes => None,
            ExtractionJobType::FunctionBytesMasked => None,
            ExtractionJobType::FunctionCFG => None,
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
    /// Write function bytes to a binary file with suffix .bin
    /// If apply_mask is true, write function masked bytes to a binary file with suffix .masked.bin
    fn write_to_bin(
        &self,
        r2p: &mut R2Pipe,
        output_dirpath: &PathBuf,
        filename_template: &str,
        apply_mask: bool,
    ) -> Result<()> {
        let func_bytes = self
            .get_bytes(r2p, apply_mask)
            .map_err(|e| anyhow::anyhow!("Failed to get bytes: {}", e))?;
        let bytes_filepath = self.get_output_filepath(output_dirpath, filename_template, "bin");
        let masked_bytes_filepath =
            self.get_output_filepath(output_dirpath, filename_template, "masked.bin");

        debug!("Writing function bytes to file: {:?}", bytes_filepath);
        std::fs::write(&bytes_filepath, func_bytes.bytes).with_context(|| {
            format!(
                "Failed to write function bytes to file: {:?}",
                bytes_filepath
            )
        })?;

        if apply_mask {
            let bytes_mask = func_bytes
                .mask
                .context("Masked bytes missing from get_bytes output")?;
            info!(
                "Writing function masked bytes to file: {:?}",
                masked_bytes_filepath
            );
            std::fs::write(&masked_bytes_filepath, bytes_mask).with_context(|| {
                format!(
                    "Failed to write function masked bytes to file: {:?}",
                    masked_bytes_filepath
                )
            })?;
        }
        Ok(())
    }

    fn write_to_json(
        &self,
        json_obj: &Value,
        output_dirpath: &PathBuf,
        filename_template: &str,
    ) -> Result<()> {
        let output_filepath = self.get_output_filepath(output_dirpath, filename_template, "json");
        debug!("Writing JSON to {:?}", output_filepath);
        let file = File::create(&output_filepath)
            .with_context(|| format!("Unable to create file {:?}", output_filepath))?;
        serde_json::to_writer(file, json_obj)
            .with_context(|| format!("Unable to write JSON to {:?}", output_filepath))?;
        Ok(())
    }

    fn write_cfg_to_json(
        &self,
        r2p: &mut R2Pipe,
        output_dirpath: &PathBuf,
        filename_template: &str,
    ) -> Result<()> {
        let cfg = self
            .get_cfg(r2p)
            .context(format!("Failed to get CFG @ {}", self.addr))?;
        // Make sure self.addr and cfg_json.addr are the same
        if self.addr != cfg.offset {
            // If they aren't, write the CFG to a JSON file with the other function's details
            warn!("Function address mismatch: {} != {}", self.addr, cfg.offset);
            let other_function = FunctionToBeProcessed::from(cfg.clone());
            other_function.write_to_json(&json!(cfg), output_dirpath, filename_template)?;
        } else {
            self.write_to_json(&json!(cfg), output_dirpath, filename_template)?;
        }
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

    fn get_bytes(&self, r2p: &mut R2Pipe, apply_mask: bool) -> Result<FuncBytes, Error> {
        let cmd_str;
        let function_bytes;
        let function_mask;
        let function_bytes_and_mask;
        let mut masked_bytes: Option<Vec<u8>> = None;

        if apply_mask {
            cmd_str = format!("p8fm @ {}", self.addr);
            debug!(
                "Getting function bytes and mask for function: `{}`",
                cmd_str
            );
            function_bytes_and_mask = r2p
                .cmd(&cmd_str)
                .context("Failed to execute `{}`")?
                .trim()
                .to_string();
            let parts: Vec<&str> = function_bytes_and_mask.split(":").collect();

            if parts.len() < 2 {
                return Err(anyhow::anyhow!(
                    "Invalid output format: expected 'bytes:mask'.\n\
                    Output from `{}`: '{}'",
                    cmd_str,
                    function_bytes_and_mask
                ));
            }
            function_bytes = hex::decode(parts[0])
                .with_context(|| format!("Failed to decode hex function bytes: '{}'", parts[0]))?;
            function_mask = hex::decode(parts[1])
                .with_context(|| format!("Failed to decode hex function mask: '{}'", parts[1]))?;

            // Ensure function_bytes and bytes_mask have the same length
            if function_bytes.len() != function_mask.len() {
                // TODO: Iteratively identify and fix missing bytes in the mask
                return Err(anyhow::anyhow!(
                    "Function bytes length ({}) and mask length ({}) do not match.\n\
                    Output from `{}`: '{}'",
                    function_bytes.len(),
                    function_mask.len(),
                    cmd_str,
                    function_bytes_and_mask
                ));
            }

            let mut masked_bytes_tmp = vec![0; function_bytes.len()];
            for i in 0..function_bytes.len() {
                masked_bytes_tmp[i] = function_bytes[i] & function_mask[i];
            }
            masked_bytes = Some(masked_bytes_tmp);
        } else {
            cmd_str = format!("p8f @ {}", self.addr);
            debug!("Getting function bytes for function: `{}`", cmd_str);
            let function_bytes_str = r2p
                .cmd(&cmd_str)
                .context("Failed to execute `{}`")?
                .trim()
                .to_string();
            function_bytes = hex::decode(function_bytes_str.clone()).with_context(|| {
                format!(
                    "Failed to decode hex function bytes: '{}'",
                    function_bytes_str
                )
            })?;
        }

        Ok(FuncBytes {
            bytes: function_bytes,
            mask: masked_bytes,
        })
    }

    fn get_basic_block_info(&self, r2p: &mut R2Pipe) -> Result<BasicBlockInfo, Error> {
        let cmd_str = format!("afbj @ {}", self.addr);
        debug!("Getting Basic Block Info for function: `{}`", cmd_str);
        let value = r2p.cmdj(&cmd_str).context("Command afbj failed")?;

        let bb_info: BasicBlockInfo =
            serde_json::from_value(value).context("Unable to convert to BasicBlockInfo struct!")?;
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
        let cmd_str = format!("axvj @ {}", self.addr);
        debug!(
            "Getting Local Variable Xref details for function: `{}`",
            cmd_str
        );
        let json = r2p.cmdj(&cmd_str).context("Command axvj failed")?;

        let local_variable_xrefs: LocalVariableXrefs = serde_json::from_value(json)
            .context("Unable to convert to LocalVariableXrefs struct!")?;
        Ok(local_variable_xrefs)
    }

    fn get_xref_details(&self, r2p: &mut R2Pipe) -> Result<Vec<FunctionXrefDetails>, Error> {
        info!("Getting xref details for function @ {}", self.addr);
        let cmd_str = format!("axffj @ {}", self.addr);
        debug!("Getting Xref details for function: `{}`", cmd_str);
        let json = r2p.cmdj(&cmd_str).context("Command axffj failed")?;
        let mut json_obj: Vec<FunctionXrefDetails> = serde_json::from_value(json)
            .context("Unable to convert to FunctionXrefDetails struct!")?;

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
        let cmd_str = format!("pdgj @ {}", self.addr);
        debug!("Getting Ghidra Decomp for function: `{}`", cmd_str);
        let json = r2p.cmdj(&cmd_str).context("Command pdgj failed")?;

        if with_annotations {
            let json_obj: DecompJSON =
                serde_json::from_value(json).context("Unable to convert to DecompJSON struct!")?;
            Ok(json_obj)
        } else {
            let json_obj: Value =
                serde_json::from_value(json).context("Unable to convert to JSON object!")?;
            let parsed_code = json_obj["code"]
                .as_str()
                .context("Unable to get code from JSON object!")?
                .to_string();
            let parsed_obj = DecompJSON {
                code: parsed_code,
                annotations: Vec::new(),
            };
            Ok(parsed_obj)
        }
    }

    fn get_cfg(&self, r2p: &mut R2Pipe) -> Result<AGFJFunc, Error> {
        let cmd_str = format!("agfj @ {}", self.addr);
        debug!("Getting CFG for function: `{}`", cmd_str);
        let json = r2p.cmdj(&cmd_str).context("Command agfj failed")?;

        // AGFJ returns an array of JSON objects, it should only ever be length 1
        let cfg: Vec<AGFJFunc> = serde_json::from_value(json.clone())
            .with_context(|| format!("Unable to convert {:?} to AGFJFunc struct!", json))?;
        if cfg.len() == 0 {
            return Err(anyhow!("No CFG found for function @ {}", self.addr));
        } else if cfg.len() > 1 {
            warn!(
                "Multiple CFGs found for function @ {}; ignoring all but the first",
                self.addr
            );
        }
        let func_cfg = cfg[0].clone();
        Ok(func_cfg)
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
            ExtractionJobType::CFG => self.extract_func_cfgs(r2p, &tmp_output_path, false),
            ExtractionJobType::FunctionCFG => self.extract_func_cfgs(r2p, &tmp_output_path, true),
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
            ExtractionJobType::FunctionBytes => {
                self.extract_function_bytes(r2p, &tmp_output_path, false)
            }
            ExtractionJobType::FunctionBytesMasked => {
                self.extract_function_bytes(r2p, &tmp_output_path, true)
            }
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

    pub fn write_function_index(&self, functions: &Vec<FunctionToBeProcessed>, output_dirpath: &PathBuf, ext: &str) -> Result<()> {
        let file = File::create(output_dirpath.join(".func-index.csv"))?;
        let mut writer = csv::Writer::from_writer(file);
        // Write header
        writer.write_record(&["name", "address", "size", "ninstrs", "nblocks", "output_path"])?;
        
        // Write function records
        for function in functions {
            let output_path = function.get_output_filepath(output_dirpath, &self.func_filename_template, ext);
            writer.write_record(&[
                &function.name,
                &function.addr.to_string(),
                &function.size.to_string(),
                &function.ninstrs.to_string(),
                &function.nblocks.to_string(),
                &output_path.to_string_lossy().to_string(),
            ])?;
        }
        writer.flush()?;
        Ok(())
    }

    pub fn get_function_list(&self, r2p: &mut R2Pipe) -> Result<&[FunctionToBeProcessed]> {
        self.function_list
            .get_or_try_init(|| self.setup_function_list(r2p))
            .map(|v| v.as_slice())
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
                info!(
                    "Skipping {:?} job for {:?}: already processed at {:?}.",
                    job_type_suffix, self.file_path, output_path
                );
                continue;
            } else if error_path.exists() && !self.retry_aborted {
                info!(
                    "Skipping {:?} job for {:?}: already processed and failed. Error log at {:?}.",
                    job_type_suffix, self.file_path, error_path
                );
                continue;
            }

            // Lazily initialize r2p if not already done.
            maybe_r2p = match self.ensure_r2_pipe(maybe_r2p, 5) {
                Ok(r2p) => Some(r2p),
                Err(e) => {
                    error!("Failed to create R2Pipe for {:?}: {e}", self.file_path);
                    None
                }
            };
            if maybe_r2p.is_none() {
                // We couldn't create a R2Pipe. We must give up on this file
                break;
            }
            let r2p = maybe_r2p.as_mut().unwrap();

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
        let function_details = self.get_function_list(r2p)?;
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
        let json = r2p.cmdj("aflj").with_context(|| format!("Failed executing aflj on {:?}", self.file_path))?;
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
        let function_details = self.get_function_list(r2p)?;
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

    pub fn extract_func_cfgs(
        &self,
        r2p: &mut R2Pipe,
        output_path: &PathBuf,
        split_by_function: bool,
    ) -> Result<()> {
        if !split_by_function {
            // All CFGs stored in a single JSON file (potentially very large)
            info!("Executing agfj @@f on {:?}", self.file_path);

            let json_raw = r2p
                .cmd("agfj @@f")
                .with_context(|| format!("Failed to extract CFGs from {:?}.", self.file_path))?;

            self.stream_write_to_json(&json_raw, output_path)
                .with_context(|| format!("Failed to write CFGs to {:?}.", self.file_path))?;
        } else {
            // CFGs stored in a separate JSON file for each function
            info!("Extracting CFGs for each function of {:?}", self.file_path);

            // The output path is a directory, create it if it doesn't exist
            let output_dirpath = output_path.clone();
            if !output_dirpath.is_dir() {
                std::fs::create_dir_all(&output_dirpath)
                    .with_context(|| format!("Failed to create directory {:?}", output_dirpath))?;
            }

            // Extract the CFGs for each function
            for function in self.get_function_list(r2p)? {
                debug!(
                    "Extracting CFG for function {:?} @ {:?}",
                    function.name, function.addr
                );
                match function.write_cfg_to_json(r2p, &output_dirpath, &self.func_filename_template)
                {
                    Ok(()) => {
                        debug!(
                            "Successfully extracted CFG for function {:?} @ {:?}",
                            function.name, function.addr
                        );
                    }
                    Err(e) => {
                        let error_path = function.get_output_filepath(
                            &output_dirpath,
                            &self.func_filename_template,
                            "error.log",
                        );
                        error!(
                            "Failed to extract CFG for function {:?} @ {:?}: {}",
                            function.name, function.addr, e
                        );
                        if let Err(write_err) = std::fs::write(&error_path, e.to_string()) {
                            error!("Failed to write error to {:?}: {}", error_path, write_err);
                        } else {
                            info!("Error stored at {:?}", error_path);
                        }
                        continue;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn extract_function_xrefs(&self, r2p: &mut R2Pipe, output_path: &PathBuf) -> Result<()> {
        let function_details = self.get_function_list(r2p)?;
        let mut function_xrefs: HashMap<String, Vec<FunctionXrefDetails>> = HashMap::new();

        info!("Extracting xrefs for each function");
        for function in function_details {
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
        let function_details = self.get_function_list(r2p)?;
        let mut function_decomp: HashMap<String, DecompJSON> = HashMap::new();

        for function in function_details {
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
        let function_details = self.get_function_list(r2p)?;
        let mut function_pcode = Vec::new();

        for function in function_details {
            let ret = self.get_ghidra_pcode(function.addr, function.ninstrs, r2p);

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
        let function_details = self.get_function_list(r2p)?;
        let mut function_pcode = Vec::new();

        for function in function_details {
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
        let function_details = self.get_function_list(r2p)?;
        let mut function_local_variable_xrefs: HashMap<String, LocalVariableXrefs> = HashMap::new();

        for function in function_details {
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

    pub fn extract_function_bytes(
        &self,
        r2p: &mut R2Pipe,
        output_dirpath: &PathBuf,
        apply_mask: bool,
    ) -> Result<()> {
        info!("Starting function bytes extraction");

        let function_details = self.get_function_list(r2p)?;
        let functions_count = function_details.len();
        if !output_dirpath.is_dir() {
            std::fs::create_dir_all(&output_dirpath)
                .with_context(|| format!("Failed to create directory {:?}", output_dirpath))?;
        }

        let mut success_count: u32 = 0;
        for function in function_details {
            debug!(
                "Function Name: {} Address: {} Size: {}",
                function.name, function.addr, function.size
            );
            match function.write_to_bin(
                r2p,
                &output_dirpath,
                &self.func_filename_template,
                apply_mask,
            ) {
                Ok(()) => {
                    debug!(
                        "Successfully extracted bytes for function {:?} @ {:?}",
                        function.name, function.addr
                    );
                    success_count += 1;
                }
                Err(e) => {
                    let error_path = function.get_output_filepath(
                        output_dirpath,
                        &self.func_filename_template,
                        "error.log",
                    );
                    error!(
                        "Failed to extract bytes for function {:?} @ {:?}: {}",
                        function.name, function.addr, e
                    );
                    if let Err(write_err) = std::fs::write(&error_path, e.to_string()) {
                        error!("Failed to write error to {:?}: {}", error_path, write_err);
                    } else {
                        info!("Error stored in {:?}", error_path);
                    }
                    continue;
                }
            }
        }

        let file_name = self.get_file_name()?;
        if success_count > 0 {
            info!(
                "Bytes extracted for {}/{} functions in {:?}",
                success_count, functions_count, file_name
            );
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "Failed to extract bytes for any function in {:?}",
                file_name
            ))
        }
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
        let cmd_str = format!("pdgsd {} @ {}", num_instructons, address);
        debug!("Getting Ghidra PCode: `{}`", cmd_str);
        let pcode_ret = r2p.cmd(&cmd_str).context("Failed to get Ghidra PCode")?;
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

    fn setup_function_list(
        &self,
        r2p: &mut R2Pipe,
    ) -> Result<Vec<FunctionToBeProcessed>> {
        info!("Setting up function list for {:?} ...", self.get_file_name());
        let json = r2p
            .cmdj("aflj")
            .with_context(|| format!("Failed executing aflj on {:?}", self.file_path))?;
        
        let array = match json {
            serde_json::Value::Array(arr) => arr,
            _ => return Err(anyhow::anyhow!("aflj output is not an array for {:?}", self.file_path)),
        };
        
        let functions_to_be_processed: Vec<FunctionToBeProcessed> = array
            .into_iter()
            .map(|func_json| {
                serde_json::from_value::<AFLJFuncDetails>(func_json)
                    .map(FunctionToBeProcessed::from)
            })
            .collect::<Result<Vec<_>, _>>()
            .with_context(|| format!("Failed to parse aflj function details for {:?}", self.file_path))?;
        
        debug!("Done getting function list for {:?}", self.get_file_name());
        Ok(functions_to_be_processed)
    }

    // Helper Functions

    /// Write a JSON object to a file
    fn write_to_json(&self, json_obj: &Value, output_filepath: &PathBuf) -> Result<()> {
        info!("Writing JSON to {:?}", output_filepath);
        let file = File::create(&output_filepath)
            .with_context(|| format!("Unable to create file {:?}", output_filepath))?;
        // Using a buffered writer to handle potentially huge JSON objects
        let writer = BufWriter::new(file);
        serde_json::to_writer(writer, &json_obj)
            .with_context(|| format!("Failed to write JSON to {:?}", output_filepath))?;
        info!("JSON written to {:?}", output_filepath);
        Ok(())
    }

    /// Stream-parse a concatenated JSON string (e.g. from `agfj @@f`)
    /// and write the combined results into a single JSON array on disk.
    /// Unlike `write_to_json`, this never builds a full in-memory Vec<Value>.
    fn stream_write_to_json(&self, json_raw: &str, output_filepath: &PathBuf) -> Result<()> {
        info!("Stream writing JSON to {:?}", output_filepath);
        // Stream the concatenated JSON values
        let iter = Deserializer::from_str(json_raw).into_iter::<Box<RawValue>>();

        // Stream the final JSON array to disk
        let file = File::create(output_filepath)
            .with_context(|| format!("Unable to create file {:?}", output_filepath))?;
        let mut writer = BufWriter::new(file);
        let mut ser = serde_json::Serializer::new(&mut writer);
        let mut seq = ser.serialize_seq(None)?; // unknown length

        for item in iter {
            match item {
                Ok(raw) => {
                    // Skip exactly "[]"
                    if raw.get().trim() != "[]" {
                        // RawValue writes the raw JSON without re-encoding
                        debug!("Serializing JSON chunk");
                        seq.serialize_element(&raw)?;
                    } else {
                        debug!("Skipping empty array");
                    }
                }
                Err(e) => {
                    // Only tolerate a *trailing* truncation
                    if e.is_eof() {
                        warn!("Trailing truncation detected. Stopping stream");
                        break;
                    } else {
                        error!("Malformed JSON chunk: {e}");
                        return Err(e).context("Malformed JSON chunk");
                    }
                }
            }
        }

        seq.end()?;
        info!("JSON stream written to {:?}", output_filepath);
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

    fn setup_r2_pipe(&self) -> Result<R2Pipe> {
        if self.r2p_config.use_curl_pdb {
            // Docs suggest this is unsafe
            env::set_var("R2_CURL", "1");
        }

        let mut args = vec![];

        // Set debug level and verbosity
        if self.r2p_config.debug {
            debug!("Creating r2 handle with debugging");
            args.push("-e log.level=0");
        } else {
            debug!("Creating r2 handle without debugging");
            args.extend(["-e log.level=1", "-2"]);
        }

        // Choose between cache or relocations (default is cache)
        if self.r2p_config.apply_relocations {
            args.push("-e bin.relocs.apply=true");
        } else {
            args.push("-e bin.cache=true");
        }

        // Set pseudo-disassembly (default is true)
        if self.r2p_config.disable_pseudo_asm {
            args.push("-e asm.pseudo=false");
        } else {
            args.push("-e asm.pseudo=true");
        }

        // Set timeout if any
        if let Some(timeout) = self.r2p_config.timeout {
            // Convert timeout from seconds to milliseconds
            let timeout_ms = timeout * 1000;
            let owned_arg_str = format!("-e anal.timeout={timeout_ms}");

            // Leak the owned String to get a &'static str so the compiler doesn't complain
            let arg_str: &'static str = Box::leak(owned_arg_str.into_boxed_str());
            args.push(arg_str);
        }

        let opts = R2PipeSpawnOptions {
            exepath: "radare2".to_owned(),
            args,
        };

        debug!(
            "Attempting to create r2pipe to analyze {:?} ...",
            self.file_path
        );
        debug!(
            "->  {:?} {:?} {:?}",
            opts.exepath,
            opts.args.join(" "),
            self.file_path
        );
        let mut r2p = match R2Pipe::in_session() {
            Some(_) => R2Pipe::open()
                .with_context(|| format!("Unable to open R2Pipe for {:?}", self.file_path))?,
            None => R2Pipe::spawn(self.file_path.to_str().unwrap(), Some(opts))
                .with_context(|| format!("Failed to spawn new R2Pipe for {:?}", self.file_path))?,
        };

        if self.r2p_config.use_curl_pdb {
            let info = r2p.cmdj("ij");
            if info.is_ok() {
                let info = info.unwrap();
                if info["bin"]["bintype"].as_str().unwrap() == "pe" {
                    debug!("PE file found. Handling symbol download!");
                    let ret = self.handle_symbols_pdb(&mut r2p);

                    if ret.is_err() {
                        warn!("Unable to get PDB info for {:?}", self.file_path);
                        info!("Continuing with analysis...");
                    } else {
                        info!("PDB info obtained successfully for {:?}", self.file_path);
                    }
                }
            }
        }

        Ok(r2p)
    }

    fn analyse_r2_pipe(&self, r2p: &mut R2Pipe) -> Result<()> {
        let analysis_mode = self.r2p_config.analysis_mode.as_str();
        debug!(
            "Executing '{}' r2 command for {}",
            analysis_mode,
            self.file_path.display()
        );
        r2p.cmd(analysis_mode)
            .with_context(|| format!("Unable to complete analysis! ({analysis_mode})"))?;
        debug!(
            "'{}' r2 command complete for {}",
            analysis_mode,
            self.file_path.display()
        );
        Ok(())
    }

    fn is_r2_pipe_alive(&self, r2p: &mut R2Pipe) -> bool {
        // Check if we can get the version
        match r2p.cmd("?V") {
            Ok(_) => true,   // The R2Pipe is alive
            Err(_) => false, // The R2Pipe is dead
        }
    }

    fn ensure_r2_pipe(&self, maybe_r2p: Option<R2Pipe>, max_attempts: u16) -> Result<R2Pipe> {
        match maybe_r2p {
            Some(r2p) => {
                let mut mutable_r2p = r2p;
                if self.is_r2_pipe_alive(&mut mutable_r2p) {
                    return Ok(mutable_r2p);
                } else {
                    return self.ensure_r2_pipe(None, max_attempts);
                }
            }
            None => {
                let mut n_attempts: u16 = 1;
                while n_attempts <= max_attempts {
                    info!("Creating R2Pipe (attempt {n_attempts}/{max_attempts})...");
                    match self.setup_r2_pipe() {
                        Ok(r2p) => {
                            let mut mutable_r2p = r2p;
                            self.analyse_r2_pipe(&mut mutable_r2p)?;
                            if self.is_r2_pipe_alive(&mut mutable_r2p) {
                                return Ok(mutable_r2p);
                            }
                        }
                        Err(e) => {
                            warn!("Failed to create R2Pipe: {e}");
                            n_attempts += 1;
                            continue;
                        }
                    }
                }
            }
        }

        bail!(
            "Failed to create R2Pipe after {} attempts. Giving up.",
            max_attempts
        );
    }
}
