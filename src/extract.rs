use crate::afij::AFIJFunctionInfo;
use crate::agcj::AGCJFunctionCallGraphs;
use anyhow::bail;
use anyhow::Error;
use anyhow::Result;
use r2pipe::R2Pipe;
use r2pipe::R2PipeSpawnOptions;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::fs::File;
use std::path::Path;
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
}

#[derive(Debug)]
pub struct FileToBeProcessed {
    pub file_path: String,
    pub output_path: String,
    pub job_type_suffix: String,
}

#[derive(Debug)]
pub struct ExtractionJob {
    pub input_path: String,
    pub input_path_type: PathType,
    pub job_type: ExtractionJobType,
    pub files_to_be_processed: Vec<FileToBeProcessed>,
    pub output_path: String, // Remove - Kept for backwards compat
}

impl std::fmt::Display for ExtractionJob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "bin_path: {} p_type: {:?} what_do: {:?}",
            self.input_path, self.input_path_type, self.job_type
        )
    }
}

// Structs related to AFLJ r2 command
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AFLJFuncDetails {
    pub offset: i64,
    pub name: String,
    pub size: i64,
    #[serde(rename = "is-pure")]
    pub is_pure: String,
    pub realsz: i64,
    pub noreturn: bool,
    pub stackframe: i64,
    pub calltype: String,
    pub cost: i64,
    pub cc: i64,
    pub bits: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub nbbs: i64,
    #[serde(rename = "is-lineal")]
    pub is_lineal: bool,
    pub ninstrs: i64,
    pub edges: i64,
    pub ebbs: i64,
    pub signature: String,
    pub minbound: i64,
    pub maxbound: i64,
    #[serde(default)]
    pub callrefs: Vec<Callref>,
    #[serde(default)]
    pub datarefs: Vec<i64>,
    pub indegree: i64,
    pub outdegree: i64,
    pub nlocals: i64,
    pub nargs: i64,
    pub bpvars: Vec<Bpvar>,
    pub spvars: Vec<Value>,
    pub regvars: Vec<Regvar>,
    pub difftype: String,
    #[serde(default)]
    pub codexrefs: Vec<Codexref>,
    #[serde(default)]
    pub dataxrefs: Vec<i64>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callref {
    pub addr: i128,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
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
    pub addr: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
}

// Structs related to AEAFJ
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
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
    pub r2: Vec<i64>,
    #[serde(rename = "@W")]
    #[serde(default)]
    pub w2: Vec<i64>,
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

impl From<(String, String, String)> for FileToBeProcessed {
    fn from(orig: (String, String, String)) -> FileToBeProcessed {
        FileToBeProcessed {
            file_path: orig.0,
            output_path: orig.1,
            job_type_suffix: orig.2,
        }
    }
}

impl ExtractionJob {
    pub fn new(input_path: &str, output_path: &str, mode: &str) -> Result<ExtractionJob, Error> {
        fn get_path_type(bin_path: &str) -> PathType {
            let fpath_md = fs::metadata(bin_path).unwrap();
            let p_type: PathType;
            if fpath_md.is_file() {
                p_type = PathType::File;
            } else if fpath_md.is_dir() {
                p_type = PathType::Dir;
            } else {
                p_type = PathType::Unk;
            }
            p_type
        }

        // This functionality is currently not being used!
        fn extraction_job_matcher(mode: &str) -> Result<ExtractionJobType, Error> {
            match mode {
                // These aren't implemented
                //"bb" => Ok(ExtractionJobType::BasicBlocks),
                "finfo" => Ok(ExtractionJobType::FuncInfo),
                "reg" => Ok(ExtractionJobType::RegisterBehaviour),
                "cfg" => Ok(ExtractionJobType::CFG),
                "xrefs" => Ok(ExtractionJobType::FunctionXrefs),
                "cg" => Ok(ExtractionJobType::CallGraphs),
                _ => bail!("Incorrect command type - got {}", mode),
            }
        }

        let p_type = get_path_type(input_path);
        let job_type = extraction_job_matcher(mode).unwrap();

        if p_type == PathType::File {
            let file = FileToBeProcessed {
                file_path: input_path.to_string(),
                output_path: output_path.to_string(),
                job_type_suffix: (*mode).to_string(),
            };
            Ok(ExtractionJob {
                input_path: input_path.to_string(),
                input_path_type: p_type,
                job_type,
                files_to_be_processed: vec![file],
                output_path: (*output_path).to_string(),
            })
        } else if p_type == PathType::Dir {
            let files = ExtractionJob::get_file_paths_dir(input_path.to_string());
            let files_with_output_path: Vec<(String, String, String)> = files
                .into_iter()
                .map(|f| (f, output_path.to_string(), mode.to_string()))
                .collect();
            let files_to_be_processed: Vec<FileToBeProcessed> = files_with_output_path
                .into_iter()
                .map(FileToBeProcessed::from)
                .collect();
            Ok(ExtractionJob {
                input_path: input_path.to_string(),
                input_path_type: p_type,
                job_type,
                files_to_be_processed,
                output_path: output_path.to_string(),
            })
        } else {
            bail!("Failed to create extraction job.")
        }
    }

    fn get_file_paths_dir(input_path: String) -> Vec<String> {
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
    pub fn extract_register_behaviour(&self, debug: &bool) {
        info!("Starting register behaviour extraction");
        let mut r2p = self.setup_r2_pipe(&self.file_path, debug);
        let function_details = self.get_function_name_list(&mut r2p);
        let mut register_behaviour_vec: HashMap<String, AEAFJRegisterBehaviour> = HashMap::new();
        info!("Executing aeafj for each function");
        for function in function_details.iter() {
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
    }

    // TODO: Refactor this so it uses the AGFJ struct
    pub fn extract_func_cfgs(&self, debug: &bool) {
        let mut fp_filename = Path::new(&self.file_path)
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();
        fp_filename = fp_filename + "_" + &self.job_type_suffix.clone();
        let f_name = format!("{}/{}.json", &self.output_path, fp_filename);
        if !Path::new(&f_name).exists() {
            info!("{} not found. Continuing processing.", f_name);
            // This creates HUGE JSON files for each files
            // Approximately 40x file size to JSON
            let mut r2p = self.setup_r2_pipe(&self.file_path, debug);
            info!("Executing agfj @@f on {}", self.file_path);
            let mut json = r2p.cmd("agfj @@f").expect("Command failed..");

            info!("Closing r2p process for {}", self.file_path);
            r2p.close();

            info!("Starting JSON fixup for {}", self.file_path);
            // Fix JSON object
            json = json.replace("[]\n", ",");
            json = json.replace("}]\n[{", "}],\n[{");
            json.insert(0, '[');
            json.push(']');
            json = json.replace("}]\n,]", "}]\n]");
            json = json.replace("\n,,[{", "\n,[{");
            json = json.replace("\n,,[{", "\n,[{");
            info!("JSON fixup finished for {}", self.file_path);

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

    pub fn extract_function_call_graphs(&self, debug: &bool) {
        info!("Starting function call graph extraction");
        let mut r2p = self.setup_r2_pipe(&self.file_path, debug);
        let json = r2p.cmd("agCj").expect("agCj command failed to execute");
        let function_call_graphs: Vec<AGCJFunctionCallGraphs> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        info!("Function call graph extracted.");
        r2p.close();
        info!("r2p closed");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_call_graphs))
    }

    pub fn extract_function_xrefs(&self, debug: &bool) {
        let mut r2p = self.setup_r2_pipe(&self.file_path, debug);
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_xrefs: HashMap<String, Vec<FunctionXrefDetails>> = HashMap::new();
        info!("Extracting xrefs for each function");
        for function in function_details.iter() {
            let ret = self.get_function_xref_details(function.offset, &mut r2p);
            function_xrefs.insert(function.name.clone(), ret);
        }
        info!("All functions processed");
        r2p.close();
        info!("r2p closed");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_xrefs))
    }

    pub fn extract_function_info(&self, debug: &bool) {
        info!("Starting function metdata extraction");
        let mut r2p = self.setup_r2_pipe(&self.file_path, debug);
        let function_details = self.get_function_name_list(&mut r2p);
        let mut function_info: Vec<Vec<AFIJFunctionInfo>> = Vec::new();
        info!("Extracting function metadata");
        for function in function_details.iter() {
            debug!("Processing {}", function.name);
            let ret = self.get_function_info(function.offset, &mut r2p);
            debug!("Metadata Collected: {:?}", ret);
            function_info.push(ret);
        }
        info!("All functions processed");
        r2p.close();
        info!("r2p closed");

        info!("Writing extracted data to file");
        self.write_to_json(&json!(function_info
            .into_iter()
            .flatten()
            .collect::<Vec<AFIJFunctionInfo>>()))
    }

    // r2 commands to structs

    fn get_function_name_list(&self, r2p: &mut R2Pipe) -> Vec<AFLJFuncDetails> {
        info!("Getting function information from binary");
        let json = r2p.cmd("aflj").expect("aflj command failed");
        let json_obj: Vec<AFLJFuncDetails> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");

        json_obj
    }

    fn get_function_xref_details(
        &self,
        function_addr: i64,
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

    fn get_function_info(&self, function_addr: i64, r2p: &mut R2Pipe) -> Vec<AFIJFunctionInfo> {
        Self::go_to_address(r2p, function_addr);
        let json = r2p.cmd("afij").expect("afij command failed");
        let json_obj: Vec<AFIJFunctionInfo> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        json_obj
    }

    // Helper Functions

    fn write_to_json(&self, json_obj: &Value) {
        let mut fp_filename = Path::new(self.file_path.as_str())
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy()
            .to_string();

        fp_filename = fp_filename + "_" + &self.job_type_suffix.clone();
        let f_name = format!("{}/{}.json", self.output_path, fp_filename);
        serde_json::to_writer(
            &File::create(&f_name).expect("Unable to create file!"),
            &json_obj,
        )
        .unwrap_or_else(|_| panic!("the world is ending: {}", f_name));
    }

    fn go_to_address(r2p: &mut R2Pipe, function_addr: i64) {
        r2p.cmd(format!("s @ {}", function_addr).as_str())
            .expect("failed to seek addr");
    }

    fn setup_r2_pipe(&self, s: &String, debug: &bool) -> R2Pipe {
        // Setup R2 pipe with options and return it
        // Could be extended to include toggling of options
        // + more args?
        let opts = if !(*debug) {
            debug!("Creating r2 handle without debugging");
            R2PipeSpawnOptions {
                exepath: "r2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=1", "-2"],
            }
        } else {
            debug!("Creating r2 handle with debugging");
            R2PipeSpawnOptions {
                exepath: "r2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=0"],
            }
        };
        debug!("Attempting to create r2pipe using {}", s);
        let mut r2p = match R2Pipe::in_session() {
            Some(_) => R2Pipe::open().expect("Unable to open R2Pipe"),
            None => R2Pipe::spawn(s, Some(opts)).expect("Failed to spawn new R2Pipe"),
        };

        debug!("Executing 'aa' r2 command for {}", s);
        r2p.cmd("aa")
            .expect("Unable to complete standard analysis!");
        debug!("'aa' r2 command complete for {}", s);
        r2p
    }
}
