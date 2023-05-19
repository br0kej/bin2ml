use anyhow::bail;
use anyhow::Error;
use anyhow::Result;
use r2pipe::R2Pipe;
use r2pipe::R2PipeSpawnOptions;
use serde_json;
use serde_json::Value;
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
#[derive(Debug)]
pub enum WhatDo {
    ExInfo, // Extract high level information from the binary (r2 ij)
    BasicBlocks,
    ESIL,
    CFG,
}
#[derive(Debug)]
pub struct ExtractJob {
    pub bin_path: String, // Refactored this but still think the name is wrong
    pub p_type: PathType,
    pub what_do: WhatDo,
    pub output_path: String, // Not sure whether to add the file paths vector to this
}

impl std::fmt::Display for ExtractJob {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "bin_path: {} p_type: {:?} what_do: {:?}",
            self.bin_path, self.p_type, self.what_do
        )
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
        fn get_whatdo_type(mode: &str) -> Result<WhatDo, Error> {
            match mode {
                "info" => Ok(WhatDo::ExInfo),
                "bb" => Ok(WhatDo::BasicBlocks),
                "esil" => Ok(WhatDo::ESIL),
                "cfg" => Ok(WhatDo::CFG),
                _ => bail!("Incorrect command type - got {}", mode),
            }
        }

        let p_type = get_path_type(bin_path);
        let what_do = get_whatdo_type(mode).unwrap();
        Ok(ExtractJob {
            bin_path: bin_path.to_string(),
            p_type,
            what_do,
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
                //let f_string = String::from(file.path().clone().to_str().unwrap());
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

    pub fn get_esil_func_info(self, s: &String) {
        let mut r2p = ExtractJob::setup_r2_pipe(s, &false);
        let mut json = r2p.cmd("aeafj @@f").expect("Command failed..");

        r2p.close();

        // Fix JSON object
        json = json.replace('}', "},");
        json.insert(0, '[');
        json.push(']');
        json = json.replace("]},\n]", "]}]");

        let json_obj: Value =
            serde_json::from_str(&json).expect("Unable to convert to JSON object!");
        ExtractJob::write_to_json(s, &self.output_path, &json_obj)
    }

    pub fn get_func_cfgs(fp: &String, output_path: &String, debug: &bool) {
        let fp_filename = Path::new(fp).file_name().expect("Unable to get filename");
        let f_name = format!("{}/{}.json", output_path, fp_filename.to_string_lossy());
        if !Path::new(&f_name).exists() {
            // This creates HUGE JSON files for each file
            // Approximately 40x file size to JSON
            let mut r2p = ExtractJob::setup_r2_pipe(fp, debug);
            let mut json = r2p.cmd("agfj @@f").expect("Command failed..");

            r2p.close();

            // Fix JSON object
            json = json.replace("[]\n", ",");
            json = json.replace("}]\n[{", "}],\n[{");
            json.insert(0, '[');
            json.push(']');
            json = json.replace("}]\n,]", "}]\n]");
            json = json.replace("\n,,[{", "\n,[{");
            json = json.replace("\n,,[{", "\n,[{");

            // TODO: Add in a log message here that states if a file was empty after being disassembled
            // by r2
            if json != "[,]" {
                #[allow(clippy::expect_fun_call)]
                // Kept in to ensure that the JSON decode error message is printed alongside the filename
                let json: Value = serde_json::from_str(&json).expect(&format!(
                    "Unable to parse json for {}: {}",
                    fp_filename.to_string_lossy(),
                    json
                ));

                ExtractJob::write_to_json(fp, output_path, &json);
            }
        } else {
            println!("Skipping {} as already exists", f_name)
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
            R2PipeSpawnOptions {
                exepath: "r2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=1", "-2"],
            }
        } else {
            R2PipeSpawnOptions {
                exepath: "r2".to_owned(),
                args: vec!["-e bin.cache=true", "-e log.level=0"],
            }
        };

        let mut r2p = match R2Pipe::in_session() {
            Some(_) => R2Pipe::open().expect("Unable to open R2Pipe"),
            None => R2Pipe::spawn(s, Some(opts)).expect("Failed to spawn new R2Pipe"),
        };

        r2p.cmd("aa")
            .expect("Unable to complete standard analysis!");
        r2p
    }
}
