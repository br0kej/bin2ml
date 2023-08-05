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
    ExInfo, // Extract high level information from the binary (r2 ij)
    BasicBlocks,
    RegisterBehaviour,
    FunctionXrefs,
    CFG,
}

#[derive(Debug)]
pub struct ExtractJob {
    pub bin_path: String, // Refactored this but still think the name is wrong
    pub p_type: PathType,
    pub extraction_job_type: ExtractionJobType,
    pub output_path: String, // Not sure whether to add the file paths vector to this
}

impl std::fmt::Display for ExtractJob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "bin_path: {} p_type: {:?} what_do: {:?}",
            self.bin_path, self.p_type, self.extraction_job_type
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

impl ExtractJob {
    pub fn new(bin_path: &str, output_path: &str, mode: &str) -> Result<ExtractJob> {
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
        fn get_whatdo_type(mode: &str) -> Result<ExtractionJobType, Error> {
            match mode {
                "info" => Ok(ExtractionJobType::ExInfo),
                "bb" => Ok(ExtractionJobType::BasicBlocks),
                "reg" => Ok(ExtractionJobType::RegisterBehaviour),
                "cfg" => Ok(ExtractionJobType::CFG),
                "xrefs" => Ok(ExtractionJobType::FunctionXrefs),
                _ => bail!("Incorrect command type - got {}", mode),
            }
        }

        let p_type = get_path_type(bin_path);
        let what_do = get_whatdo_type(mode).unwrap();
        Ok(ExtractJob {
            bin_path: bin_path.to_string(),
            p_type,
            extraction_job_type: what_do,
            output_path: output_path.to_string(),
        })
    }

    pub fn get_file_paths_dir(&self) -> Vec<String> {
        let mut str_vec: Vec<String> = Vec::new();
        for file in WalkDir::new(&self.bin_path)
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

    pub fn get_func_listings(&self, print: bool) -> Option<Value> {
        let opts = R2PipeSpawnOptions {
            exepath: "radare2".to_owned(),
            ..Default::default()
        };

        let mut r2p = match R2Pipe::in_session() {
            Some(_) => R2Pipe::open().expect("Unable to open R2Pipe"),
            None => R2Pipe::spawn(&self.bin_path, Some(opts)).expect("Failed to spawn new R2Pipe"),
        };

        let json = r2p.cmdj("ij").expect("Command failed..");
        if print {
            println!(
                "{}",
                serde_json::to_string_pretty(&json).expect("Failed to convert json to pretty json")
            );
            None
        } else {
            Some(json)
        }
    }

    pub fn get_bb_func_info(&self, s: &String) {
        let mut r2p = ExtractJob::setup_r2_pipe(s, &false);
        let mut json = r2p.cmd("afbj @@f").expect("Command failed..");

        r2p.close();

        // Fix JSON object
        json = json.replace("}]\n", "}],\n");
        json.insert(0, '[');
        json.push(']');
        // Replace the very last one to make sure its a valid JSON object
        json = json.replace("}],\n]", "}]\n]");

        let json_obj: Value =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        ExtractJob::write_to_json(s, &self.output_path, &json_obj)
    }

    pub fn get_register_behaviour(fp: &String, output_path: &String, debug: &bool) {
        info!("Starting register behaviour extraction");
        let mut r2p = ExtractJob::setup_r2_pipe(fp, debug);
        let function_details = ExtractJob::get_function_details(&mut r2p);
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
        ExtractJob::write_to_json(fp, output_path, &json!(register_behaviour_vec))
    }

    fn get_function_details(r2p: &mut R2Pipe) -> Vec<AFLJFuncDetails> {
        info!("Getting function information from binary");
        let json = r2p.cmd("aflj").expect("aflj command failed");
        let json_obj: Vec<AFLJFuncDetails> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");

        json_obj
    }

    fn get_function_xref_details(function_addr: i64, r2p: &mut R2Pipe) /*-> Vec<FunctionXrefDetails> */
    {
        info!("Getting function xref details");
        r2p.cmd(format!("s @ {}", function_addr).as_str())
            .expect("failed to seek addr");
        let json = r2p.cmd("axffj").expect("axffj command failed");
        let mut json_obj: Vec<FunctionXrefDetails> =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        debug!("Replacing all CALL xrefs with actual function name");
        if json_obj.len() > 0 {
            debug!("Replacing all CALL xrefs with actual function name");
            for element in json_obj.iter_mut() {
                if element.type_field == "CALL" {
                    let function_name = r2p
                        .cmd(format!("afi. @ {}", &element.ref_field).as_str())
                        .expect("afi. command failed");
                    element.name = function_name;
                }
            }
            println!("{:?}", json_obj);
        };
    }

    pub fn get_func_cfgs(fp: &String, output_path: &String, debug: &bool) {
        let fp_filename = Path::new(fp).file_name().expect("Unable to get filename");
        let f_name = format!("{}/{}.json", output_path, fp_filename.to_string_lossy());
        if !Path::new(&f_name).exists() {
            info!("{} not found. Continuing processing.", f_name);
            // This creates HUGE JSON files for each file
            // Approximately 40x file size to JSON
            let mut r2p = ExtractJob::setup_r2_pipe(fp, debug);
            info!("Executing agfj @@f on {}", fp);
            let mut json = r2p.cmd("agfj @@f").expect("Command failed..");

            info!("Closing r2p process for {}", fp);
            r2p.close();

            info!("Starting JSON fixup for {}", fp);
            // Fix JSON object
            json = json.replace("[]\n", ",");
            json = json.replace("}]\n[{", "}],\n[{");
            json.insert(0, '[');
            json.push(']');
            json = json.replace("}]\n,]", "}]\n]");
            json = json.replace("\n,,[{", "\n,[{");
            json = json.replace("\n,,[{", "\n,[{");
            info!("JSON fixup finished for {}", fp);

            if json != "[,]" {
                #[allow(clippy::expect_fun_call)]
                // Kept in to ensure that the JSON decode error message is printed alongside the filename
                let json: Value = serde_json::from_str(&json).expect(&format!(
                    "Unable to parse json for {}: {}",
                    fp_filename.to_string_lossy(),
                    json
                ));

                ExtractJob::write_to_json(fp, output_path, &json);
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

    fn write_to_json(fp: &String, output_path: &str, json_obj: &Value) {
        let fp_filename = Path::new(fp)
            .file_name()
            .expect("Unable to get filename")
            .to_string_lossy();
        let f_name = format!("{}/{}.json", output_path, fp_filename);
        serde_json::to_writer(
            &File::create(&f_name).expect("Unable to create file!"),
            &json_obj,
        )
        .unwrap_or_else(|_| panic!("the world is ending: {}", f_name));
    }

    fn setup_r2_pipe(s: &String, debug: &bool) -> R2Pipe {
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
