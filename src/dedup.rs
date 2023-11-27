use crate::networkx::{CallGraphFuncWithMetadata, NetworkxDiGraph};
use anyhow::Result;
use indicatif::ParallelProgressIterator;
use itertools::Itertools;
use prettytable::row;
use prettytable::Table;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fs::{read_to_string, File};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::string::String;

use std::sync::{Arc, Mutex};
use std::{fs, vec};
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

#[derive(Debug)]
pub struct OneHopCGCorpus {
    pub loaded_data: Vec<NetworkxDiGraph<CallGraphFuncWithMetadata>>,
    pub filepaths: Vec<String>,
    pub output_path: String,
}

impl OneHopCGCorpus {
    pub fn new(directory: &String, output_path: &String) -> Result<OneHopCGCorpus> {
        if !Path::new(output_path).exists() {
            fs::create_dir(output_path).expect("Failed to create output directory!");
            info!("Output path not found - Creating {}", output_path)
        }

        let mut filepaths = Vec::new();
        let mut fp_binaries = Vec::new();

        // Load all JSON filepaths
        for file in WalkDir::new(directory)
            .into_iter()
            .filter_map(|file| file.ok())
        {
            if file.path().to_string_lossy().ends_with(".json") {
                filepaths.push(file.clone().path().to_string_lossy().to_string());
            }
        }

        // Process the file paths to get the associated binary of each path
        for file in &filepaths {
            let binary_intermediate = Path::new(file).parent().unwrap().file_name().unwrap();
            let binary = binary_intermediate
                .to_string_lossy()
                .split("_")
                .nth(1)
                .unwrap()
                .to_string();

            fp_binaries.push(binary)
        }

        // Generate binary specific filepath vectors
        let unqiue_binaries: Vec<_> = fp_binaries.iter().unique().collect();
        let mut unique_binaries_fps: Vec<Vec<String>> = vec![Vec::new(); unqiue_binaries.len()];

        for (file, binary) in filepaths.iter().zip(fp_binaries.iter()) {
            unique_binaries_fps
                [unqiue_binaries.iter().position(|&x| x == binary).unwrap() as usize]
                .push(file.clone());
        }

        // Create a Vec of Vec<String> where each vec is a unique binary
        let deduped_data = Arc::new(Mutex::new(vec![Vec::new(); unqiue_binaries.len()]));
        let deduped_paths = Arc::new(Mutex::new(vec![Vec::new(); unqiue_binaries.len()]));

        info!("Loading the filepaths");
        unique_binaries_fps
            .par_iter()
            .progress()
            .enumerate()
            .for_each(|(idx, fp_subset)| {
                let mut subset_loaded_data = Vec::new();

                for ele in fp_subset.iter() {
                    let data =
                        read_to_string(&ele).expect(&format!("Unable to read file - {:?}", ele));

                    let json: NetworkxDiGraph<CallGraphFuncWithMetadata> =
                        serde_json::from_str(&data)
                            .expect(&format!("Unable to load function data from {}", ele));

                    if !json.nodes.is_empty() {
                        subset_loaded_data.push(Some(json))
                    } else {
                        subset_loaded_data.push(None)
                    }
                }

                //info!("Len Pre Filtering: {:?}", fp_subset.len());
                //info!("Removing any None loads");
                subset_loaded_data.retain(|c| c.is_some());

                //info!("Starting to deduplicate the corpus");
                let (subset_loaded_data, fp_subset) =
                    Self::dedup_corpus(&mut subset_loaded_data, fp_subset.to_vec());
                let subset_loaded_data: Vec<NetworkxDiGraph<_>> =
                    subset_loaded_data.into_iter().filter_map(|x| x).collect();

                deduped_data
                    .lock()
                    .unwrap()
                    .insert(idx, subset_loaded_data.clone());
                deduped_paths.lock().unwrap().insert(idx, fp_subset);
            });
        info!("File loading complete");
        let deduped_data = Arc::try_unwrap(deduped_data).unwrap().into_inner().unwrap();
        let deduped_paths = Arc::try_unwrap(deduped_paths)
            .unwrap()
            .into_inner()
            .unwrap();

        let loaded_data = deduped_data.into_iter().flatten().collect();
        let filepaths: Vec<String> = deduped_paths.into_iter().flatten().collect();
        let filepaths = filepaths.iter().map(|x| x.to_string()).collect();

        info!("Returning One Hop CG Corpus Struct");

        Ok(OneHopCGCorpus {
            loaded_data,
            filepaths,
            output_path: output_path.to_string(),
        })
    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    // This is very slow O(N)^2
    fn dedup_corpus(
        data: &mut Vec<Option<NetworkxDiGraph<CallGraphFuncWithMetadata>>>,
        mut filepaths: Vec<String>,
    ) -> (
        Vec<Option<NetworkxDiGraph<CallGraphFuncWithMetadata>>>,
        Vec<String>,
    ) {
        //info!("Creating the removal index");

        let mut seen = HashSet::new();
        let mut indices_to_remove = Vec::new();
        for (i, data_ele) in data.iter_mut().enumerate() {
            let hash_value = Self::calculate_hash(&data_ele);

            if seen.contains(&hash_value) {
                indices_to_remove.push(i)
            } else {
                seen.insert(hash_value);
            }
        }
        //info!("Starting the duplicate removal!");
        for ele in indices_to_remove.iter().rev() {
            data.remove(*ele);
            filepaths.remove(ele.clone());
        }
        return (data.to_vec(), filepaths);
    }

    pub fn save_corpus(self) {
        info!("Saving Deduplicated files...");
        //for (data_ele, filepath) in self.loaded_data.par_iter().zip(self.filepaths.par_iter()) {
        // need last two bits
        self.loaded_data
            .par_iter()
            .zip(self.filepaths.par_iter())
            .progress()
            .for_each(|(data_ele, filepath)| {
                let fixed_path: Vec<_> = Path::new(filepath)
                    .components()
                    .rev()
                    .take(2)
                    .collect::<Vec<_>>();

                let fixed_path = fixed_path
                    .iter()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .rev()
                    .collect::<Vec<String>>();

                let dirs = format!("{}{}", self.output_path, fixed_path[0]);
                fs::create_dir_all(&dirs).expect("Failed to create output directory!");

                let fixed_path = format!("{}/{}", dirs, fixed_path[1]);
                debug!("Path: {:?}", fixed_path);
                serde_json::to_writer(
                    &File::create(fixed_path).expect("Failed to create writer"),
                    &data_ele,
                )
                .expect("Unable to write JSON");
            });
        info!("All files saved!");
    }
}
