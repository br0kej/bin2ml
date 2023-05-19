use anyhow::Result;
use itertools::Itertools;
use prettytable::row;
use prettytable::Table;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs::{read_to_string, File};
use std::hash::{Hash, Hasher};
use std::string::String;
use std::vec;
use walkdir::{DirEntry, WalkDir};

#[derive(Serialize, Deserialize, Debug)]
pub struct DedupEntry {
    name: String,
    hash: u64,
    data: String,
    triple: String,
}

impl From<(String, u64, String, String)> for DedupEntry {
    fn from(orig: (String, u64, String, String)) -> DedupEntry {
        DedupEntry {
            name: orig.0,
            hash: orig.1,
            data: orig.2,
            triple: orig.3,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EsilFuncString {
    func_name: String,
    esil_str: String,
}
impl Hash for EsilFuncString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.func_name.hash(state);
        self.esil_str.hash(state);
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EsilFuncStringFile {
    pub filename: String,
    pub binary_name: String,
    pub esil_fstrs: Option<HashMap<String, String>>,
    pub arch: String,
}

impl EsilFuncStringFile {
    pub fn new(filename: String, arch: String) -> Result<EsilFuncStringFile> {
        let binary_name = filename.split('_').last().unwrap().to_string();
        Ok(EsilFuncStringFile {
            filename: filename.clone(),
            binary_name,
            esil_fstrs: EsilFuncStringFile::load_and_deserialize(filename),
            arch,
        })
    }

    fn load_and_deserialize(filename: String) -> Option<HashMap<String, String>> {
        let data =
            read_to_string(&filename).expect(&format!("Unable to read file - {:?}", filename));

        let json: HashMap<String, String> = serde_json::from_str(&data)
            .expect(&format!("Unable to load function data from {}", filename));

        if !json.is_empty() {
            Some(json)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct EsilFuncStringCorpus {
    pub loaded_data: Option<Vec<EsilFuncStringFile>>,
    pub filepaths: Vec<DirEntry>,
    pub binary_name_index: Vec<String>,
    pub uniq_binaries: Vec<String>,
    pub arch_index: Vec<String>,
}

/// A collection of processed Esil Function String files
impl EsilFuncStringCorpus {
    pub fn new(directory: &String) -> Result<EsilFuncStringCorpus> {
        let mut filepaths = Vec::new();
        let mut binary_name_index = Vec::new();
        let mut uniq_binaries = Vec::new();
        let mut arch_index = Vec::new();

        for file in WalkDir::new(directory)
            .into_iter()
            .filter_map(|file| file.ok())
        {
            if file.path().to_string_lossy().ends_with(".json") {
                filepaths.push(file.clone());

                let file_path_string = file
                    .path()
                    .file_name()
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                let binary_name = file_path_string.split('_').last().unwrap().to_string();
                let arch = file_path_string.split('_').next().unwrap().to_string();
                binary_name_index.push(binary_name.clone());
                arch_index.push(arch.clone());
                if !uniq_binaries.contains(&binary_name) {
                    uniq_binaries.push(binary_name.clone())
                }
            }
        }
        Ok(EsilFuncStringCorpus {
            loaded_data: None,
            filepaths,
            binary_name_index,
            uniq_binaries,
            arch_index,
        })
    }

    /// Get the indexes of the filepaths that contain a given target binary name
    fn get_target_binary_fp_idxs(&self, target_binary_name: &String) -> Vec<usize> {
        #[allow(clippy::needless_borrowed_reference)]
        // In this case, the &ref r seems to be necessary
        let target_binary_fp_idxs = self
            .binary_name_index
            .iter()
            .enumerate()
            .filter(|(_, &ref r)| r == target_binary_name)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        target_binary_fp_idxs
    }

    /// Load a subset of the data given a vector of indexes corresponding to elements in the
    /// filepaths member
    fn load_subset(&self, target_binary_fp_idxs: &Vec<usize>) -> Vec<EsilFuncStringFile> {
        let mut loaded_subset_data = Vec::new();
        for idx in target_binary_fp_idxs {
            let loaded_file_data = EsilFuncStringFile::new(
                self.filepaths[*idx].path().to_string_lossy().to_string(),
                self.arch_index[*idx].clone(),
            )
            .expect(&format!(
                "Unable to load {:?}",
                self.filepaths[*idx].file_name().to_str()
            ));
            loaded_subset_data.push(loaded_file_data);
        }
        loaded_subset_data
    }

    /// Generic hashing helper function
    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    /// Hash each item in a loaded subset using both the key and value within each hashmap entry
    fn hash_subset_key_val(
        &self,
        loaded_subset: Vec<EsilFuncStringFile>,
    ) -> Vec<(String, u64, String, String)> {
        let mut func_hash_tuples: Vec<(String, u64, String, String)> = Vec::new();

        for file in loaded_subset {
            for (k, v) in &file
                .esil_fstrs
                .expect(&format!("Unable to unwrap for {}", file.filename))
            {
                let obj_to_hash = EsilFuncString {
                    func_name: k.clone(),
                    esil_str: v.clone(),
                };
                let hash_out = Self::calculate_hash(&obj_to_hash);
                func_hash_tuples.push((k.clone(), hash_out, v.clone(), file.arch.clone()))
            }
        }
        func_hash_tuples
    }

    /// Hash each item in a loaded subset using just the value within each hashmap entry
    fn hash_subset_val(
        &self,
        loaded_subset: Vec<EsilFuncStringFile>,
    ) -> Vec<(String, u64, String, String)> {
        let mut func_hash_tuples: Vec<(String, u64, String, String)> = Vec::new();

        for file in loaded_subset {
            for (k, v) in &file
                .esil_fstrs
                .expect(&format!("Unable to unwrap for {}", file.filename))
            {
                let obj_to_hash = EsilFuncString {
                    func_name: k.clone(),
                    esil_str: v.clone(),
                };
                let hash_out = Self::calculate_hash(&obj_to_hash);
                func_hash_tuples.push((k.clone(), hash_out, v.clone(), file.arch.clone()))
            }
        }
        func_hash_tuples
    }

    /// Get the unique values within a collection of function has tuples using the
    /// hash as the value to derive unique values
    fn get_uniques(&self, func_hash_tuples: Vec<(String, u64, String, String)>) -> Vec<DedupEntry> {
        func_hash_tuples
            .into_iter()
            .unique_by(|s| s.1)
            .map(DedupEntry::from)
            .collect()
    }

    /// Generate hash statistics from a func hash tuple collection
    fn hash_stats(&self, original_len: usize, unique_func_has_tuples: &Vec<DedupEntry>) {
        let unique_len = unique_func_has_tuples.len();
        let percent_difference: f32 =
            ((original_len as f32 - unique_len as f32) / original_len as f32) * 100.0;

        let mut table = Table::new();
        table.add_row(row!["With Dups", "Without Dups", "Num Removed", "% diff"]);
        table.add_row(row![
            original_len,
            unique_len,
            original_len - unique_len,
            percent_difference
        ]);

        table.printstd();
    }

    pub fn dedup_subset(
        &self,
        target_binary_name: &String,
        print_stats: bool,
        just_stats: bool,
        hash_just_value: bool,
    ) {
        let fp_idxs = self.get_target_binary_fp_idxs(target_binary_name);
        let loaded_subset = self.load_subset(&fp_idxs);

        let func_hash_tuples: Vec<(String, u64, String, String)> = if hash_just_value {
            self.hash_subset_val(loaded_subset)
        } else {
            self.hash_subset_key_val(loaded_subset)
        };

        let original_len = func_hash_tuples.len();
        let unique_func_hash_tuples = self.get_uniques(func_hash_tuples);

        if print_stats || just_stats {
            println!("Stats for {}", target_binary_name);
            self.hash_stats(original_len, &unique_func_hash_tuples);
        }

        if !just_stats {
            let uniques_to_drop = json!(unique_func_hash_tuples);
            let fname_string = format!("{}-dedup.json", &target_binary_name);
            serde_json::to_writer(
                &File::create(fname_string).expect("Failed to create writer"),
                &uniques_to_drop,
            )
            .expect("Unable to write JSON");
        }
    }
}
