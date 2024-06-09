use crate::extract::{PCodeJSONWithFuncName, PCodeJsonWithBB, PCodeJsonWithBBAndFuncName};
use crate::files::FormatMode;
use crate::utils::get_save_file_path;
use enum_as_inner::EnumAsInner;
use rayon::iter::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::mpsc::channel;

#[derive(Serialize, Deserialize, Debug, EnumAsInner, Clone)]
#[serde(untagged)]
pub enum PCodeDataTypes {
    PCodeJSON(PCodeJSONWithFuncName),
    PCodeJsonWithBB(PCodeJsonWithBBAndFuncName),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum PCodeFileTypes {
    PCodeJsonFile,
    PCodeWithBBFile,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PCodeFile {
    pub filename: PathBuf,
    pub pcode_obj: Option<Vec<PCodeDataTypes>>,
    pub output_path: PathBuf,
    pub min_blocks: Option<u16>,
    pub instruction_pairs: bool,
    pub format_type: FormatMode,
    pub pcode_file_type: PCodeFileTypes,
}

pub trait PCodeToNLP {
    fn get_linear_walk(&self, pairs: bool) -> Vec<String>;
    fn get_func_string(&self) -> HashMap<String, String>;
}

impl PCodeToNLP for PCodeJSONWithFuncName {
    fn get_linear_walk(&self, pairs: bool) -> Vec<String> {
        if pairs {
            let pcode: &Vec<String> = self.pcode.pcode.as_ref();
            let ret = pcode.iter().zip(pcode.iter().skip(1)).collect::<Vec<_>>();

            let ret = ret
                .iter()
                .map(|(x, y)| format!("{} ---- {}", x, y))
                .collect();
            ret
        } else {
            self.pcode.pcode.clone()
        }
    }

    fn get_func_string(&self) -> HashMap<String, String> {
        let mut func_string_mapping: HashMap<String, String> = HashMap::new();
        let func_string = self
            .pcode
            .pcode
            .iter()
            .fold(String::new(), |acc, x| format!("{} {}", acc, x));
        let func_string = func_string.trim().to_string();
        func_string_mapping.insert(self.function_name.clone(), func_string);
        func_string_mapping
    }
}

impl PCodeToNLP for PCodeJsonWithBBAndFuncName {
    fn get_linear_walk(&self, pairs: bool) -> Vec<String> {
        let pcode_blocks: &Vec<PCodeJsonWithBB> = self.pcode_blocks.as_ref();
        let mut pcode_output: Vec<String> = Vec::new();

        if pairs {
            for block in pcode_blocks {
                let pcode: &Vec<String> = block.pcode.as_ref();
                let ret_inner = pcode.iter().zip(pcode.iter().skip(1)).collect::<Vec<_>>();
                let ret_inner: Vec<String> = ret_inner
                    .iter()
                    .map(|(x, y)| format!("{} ---- {}", x, y))
                    .collect();
                pcode_output.push(ret_inner.join("\n"));
            }
        } else {
            for block in pcode_blocks {
                let pcode: &Vec<String> = block.pcode.as_ref();
                pcode_output.push(pcode.join("\n"));
            }
        }

        pcode_output
    }

    fn get_func_string(&self) -> HashMap<String, String> {
        let mut func_string_mapping: HashMap<String, String> = HashMap::new();
        let pcode_blocks: &Vec<PCodeJsonWithBB> = self.pcode_blocks.as_ref();
        let mut func_string: Vec<String> = Vec::new();
        for block in pcode_blocks {
            let pcode: &Vec<String> = block.pcode.as_ref();
            func_string.push(pcode.join(" "))
        }

        let func_string = func_string.join(" ");
        func_string_mapping.insert(self.function_name.clone(), func_string);
        func_string_mapping
    }
}

impl PCodeFile {
    #[allow(dead_code)]
    pub fn new(
        filename: PathBuf,
        output_path: PathBuf,
        min_blocks: Option<u16>,
        instruction_pairs: bool,
        format_type: FormatMode,
        pcode_file_type: PCodeFileTypes,
    ) -> Self {
        PCodeFile {
            filename,
            pcode_obj: None,
            output_path,
            min_blocks,
            instruction_pairs,
            format_type,
            pcode_file_type,
        }
    }

    pub fn load_and_deserialize(&mut self) -> Result<(), ()> {
        let data = read_to_string(&self.filename);

        if let Ok(data) = data {
            let pcode_obj: Vec<PCodeDataTypes> = serde_json::from_str(&data).unwrap();
            self.set_pcode_obj(pcode_obj);
            Ok(())
        } else {
            error!("Error reading file: {}", self.filename.to_string_lossy());
            Err(())
        }
    }

    pub fn set_pcode_obj(&mut self, pcode_obj: Vec<PCodeDataTypes>) {
        self.pcode_obj = Some(pcode_obj);
    }

    pub fn execute_data_generation(mut self) {
        self.process_pcode_json()
    }

    /// Process a PCodeJSON file and output each PCode instruction as a line within a text file
    ///
    /// This function is able to output create a text file with either single PCode
    /// instructions per line or pairs of PCode instructions. A single pair of PCode
    /// corresponds to two instructions that are sequential and are only ever
    /// sampled from within a given function (i.e you won't get the last of one function and
    /// then the first of another)
    fn pcode_json_single_instruction(&mut self, fname_string: PathBuf) {
        let pcode_obj = self.pcode_obj.clone().unwrap();

        let (sender, receiver) = channel();

        pcode_obj.par_iter().for_each_with(sender, |s, func| {
            s.send(
                func.as_p_code_json()
                    .unwrap()
                    .get_linear_walk(self.instruction_pairs),
            )
            .unwrap()
        });

        let res: Vec<Vec<String>> = receiver.iter().collect();
        let write_file = File::create(fname_string).unwrap();
        let mut writer = BufWriter::new(&write_file);

        for func in res {
            for pcode_ins in func {
                writer
                    .write_all(pcode_ins.as_bytes())
                    .expect("Unable to write bytes.");
                writer.write_all(b"\n").expect("Unable to write bytes.");
            }
        }
    }

    /// Process a PCodeJSON file and output each functions PCode as a function string
    ///
    /// A function string is each pcode instruction within a function concatenated together
    fn pcode_json_func_as_string(&mut self, fname_string: PathBuf) {
        let pcode_obj = self.pcode_obj.clone().unwrap();

        let (sender, receiver) = channel();

        pcode_obj.par_iter().for_each_with(sender, |s, func| {
            s.send(func.as_p_code_json().unwrap().get_func_string())
                .unwrap()
        });

        let res: Vec<HashMap<String, String>> = receiver.iter().collect();
        let write_file = File::create(fname_string).unwrap();
        let mut writer = BufWriter::new(&write_file);

        let string = serde_json::to_string(&res).unwrap();
        writer
            .write_all(string.as_bytes())
            .expect("Unable to write bytes.");
    }

    /// Build the output filepath for a given PCodeFile based on the desired output
    /// format type and input PCode file type.
    fn get_output_filepath(&self) -> PathBuf {
        let fname_string: PathBuf =
            get_save_file_path(&self.filename, &self.output_path, None, None, None);

        let fname_string = match (self.format_type, self.pcode_file_type.clone()) {
            (FormatMode::SingleInstruction, PCodeFileTypes::PCodeJsonFile) => {
                if self.instruction_pairs {
                    format!("{}-pcode-pairs.txt", fname_string.to_string_lossy())
                } else {
                    format!("{}-pcode-singles.txt", fname_string.to_string_lossy())
                }
            }
            (FormatMode::FuncAsString, PCodeFileTypes::PCodeJsonFile) => {
                format!("{}-pcode-funcstrings.json", fname_string.to_string_lossy())
            }
            (FormatMode::SingleInstruction, PCodeFileTypes::PCodeWithBBFile) => {
                if self.instruction_pairs {
                    format!("{}-pcode-pairs.txt", fname_string.to_string_lossy())
                } else {
                    format!("{}-pcode-singles.txt", fname_string.to_string_lossy())
                }
            }
            (FormatMode::FuncAsString, PCodeFileTypes::PCodeWithBBFile) => {
                format!(
                    "{}-pcode-funcstrings-bb-metadata.json",
                    fname_string.to_string_lossy()
                )
            }
            _ => {
                error!(
                    "Invalid Format Mode - Got {:?} and {:?}",
                    self.format_type, self.pcode_file_type
                );
                exit(1)
            }
        };

        PathBuf::from(fname_string)
    }

    /// Process a PCodeJSON file and output the desired format type
    ///
    /// This is a helper function which matches on the format type to
    /// trigger the appropriate processing function
    fn process_pcode_json(&mut self) {
        let fname_string: PathBuf = self.get_output_filepath();

        if !Path::new(&fname_string).exists() {
            let ret = self.load_and_deserialize();

            if ret.is_err() {
                error!("Error loading and deserializing PCode file");
                exit(1)
            }

            match (self.format_type, self.pcode_file_type.clone()) {
                (FormatMode::SingleInstruction, PCodeFileTypes::PCodeJsonFile) => {
                    self.pcode_json_single_instruction(fname_string);
                }
                (FormatMode::FuncAsString, PCodeFileTypes::PCodeJsonFile) => {
                    self.pcode_json_func_as_string(fname_string);
                }
                (FormatMode::SingleInstruction, PCodeFileTypes::PCodeWithBBFile) => {
                    self.pcode_json_with_bb_info_single_instruction(fname_string);
                }
                (FormatMode::FuncAsString, PCodeFileTypes::PCodeWithBBFile) => {
                    self.pcode_json_with_bb_info_func_as_string(fname_string);
                }

                _ => {
                    println!("Invalid Format Mode");
                }
            }
        } else {
            error!("File already exists: {:?}", fname_string);
        }
    }

    fn pcode_json_with_bb_info_single_instruction(&mut self, fname_string: PathBuf) {
        let pcode_obj = self.pcode_obj.clone().unwrap();

        let (sender, receiver) = channel();

        pcode_obj.par_iter().for_each_with(sender, |s, func| {
            s.send(
                func.as_p_code_json_with_bb()
                    .unwrap()
                    .get_linear_walk(self.instruction_pairs),
            )
            .unwrap()
        });

        let res: Vec<Vec<String>> = receiver.iter().collect();
        let write_file = File::create(fname_string).unwrap();
        let mut writer = BufWriter::new(&write_file);

        for func in res {
            for pcode_ins in func {
                writer
                    .write_all(pcode_ins.as_bytes())
                    .expect("Unable to write bytes.");
                writer.write_all(b"\n").expect("Unable to write bytes.");
            }
        }
    }

    fn pcode_json_with_bb_info_func_as_string(&mut self, fname_string: PathBuf) {
        let pcode_obj = self.pcode_obj.clone().unwrap();

        let (sender, receiver) = channel();

        pcode_obj.par_iter().for_each_with(sender, |s, func| {
            s.send(func.as_p_code_json_with_bb().unwrap().get_func_string())
                .unwrap()
        });

        let res: Vec<HashMap<String, String>> = receiver.iter().collect();
        let write_file = File::create(fname_string).unwrap();
        let mut writer = BufWriter::new(&write_file);

        for func in res {
            let string = serde_json::to_string(&func).unwrap();
            writer
                .write_all(string.as_bytes())
                .expect("Unable to write bytes.");
        }
    }
}