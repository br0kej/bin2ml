use crate::networkx::{CallGraphNodeTypes, NetworkxDiGraph};
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
pub struct CGCorpus {
    pub filepaths: Vec<String>,
    pub output_path: String,
    pub filepath_format: String,
}

impl CGCorpus {
    pub fn new(
        directory: &String,
        output_path: &String,
        filepath_format: &String,
    ) -> Result<CGCorpus> {
        if !Path::new(output_path).exists() {
            fs::create_dir(output_path).expect("Failed to create output directory!");
            info!("Output path not found - Creating {}", output_path)
        }

        let mut filepaths = Vec::new();

        // Load all JSON filepaths
        for file in WalkDir::new(directory)
            .into_iter()
            .filter_map(|file| file.ok())
        {
            if file.path().to_string_lossy().ends_with(".json") {
                filepaths.push(file.clone().path().to_string_lossy().to_string());
            }
        }

        info!("Returning One Hop CG Corpus Struct");

        Ok(CGCorpus {
            filepaths,
            output_path: output_path.to_string(),
            filepath_format: filepath_format.to_string(),
        })
    }

    fn calculate_hash<T: Hash>(t: &T) -> u64 {
        let mut s = DefaultHasher::new();
        t.hash(&mut s);
        s.finish()
    }

    fn dedup_corpus<N: Hash>(
        data: &mut Vec<Option<NetworkxDiGraph<N>>>,
        filepaths: &mut Vec<String>,
    ) {
        debug!("Creating the removal index");

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
        debug!("Starting the duplicate removal!");
        for ele in indices_to_remove.iter().rev() {
            data.remove(*ele);
            filepaths.remove(*ele);
        }
    }

    fn get_binary_name_cisco(filepath: &String) -> String {
        // Example: x86-gcc-9-O3_nping_cg-onehopcgcallers-meta
        let binary_intermediate = Path::new(filepath).parent().unwrap().file_name().unwrap();
        binary_intermediate
            .to_string_lossy()
            .split('_')
            .nth(1)
            .unwrap()
            .to_string()
    }
    fn get_binary_name_binkit(filepath: &String) -> String {
        // Example: tar-1.34_gcc-8.2.0_x86_32_O3_rmt_cg-onehopcgcallers-meta
        let binary_intermediate = Path::new(filepath).parent().unwrap().file_name().unwrap();
        binary_intermediate
            .to_string_lossy()
            .split('_')
            .rev()
            .nth(1)
            .unwrap()
            .to_string()
    }
    pub fn process_corpus(self) {
        let mut fp_binaries = Vec::new();
        // Process the file paths to get the associated binary of each path
        info!("Processing Filepaths to get binaries");
        for file in &self.filepaths {
            let binary = match self.filepath_format.as_str() {
                "cisco" => Self::get_binary_name_cisco(file),
                "binkit" => Self::get_binary_name_binkit(file),
                _ => unreachable!(),
            };
            debug!("Extracted Binary Name: {:?} from {:?}", binary, file);
            fp_binaries.push(binary)
        }

        // Generate binary specific filepath vectors
        let unqiue_binaries: Vec<_> = fp_binaries.iter().unique().collect();
        let mut unique_binaries_fps: Vec<Vec<String>> = vec![Vec::new(); unqiue_binaries.len()];

        for (file, binary) in self.filepaths.iter().zip(fp_binaries.iter()) {
            unique_binaries_fps[unqiue_binaries.iter().position(|&x| x == binary).unwrap()]
                .push(file.clone());
        }

        info!("Loading the filepaths");
        unique_binaries_fps
            .par_iter()
            .progress()
            .enumerate()
            .for_each(|(idx, fp_subset)| {
                let mut subset_loaded_data: Vec<std::option::Option<NetworkxDiGraph<_>>> =
                    Vec::new();

                for ele in fp_subset.iter() {
                    let data =
                        read_to_string(ele).expect(&format!("Unable to read file - {:?}", ele));

                    let json: NetworkxDiGraph<CallGraphNodeTypes> =
                        serde_json::from_str::<NetworkxDiGraph<CallGraphNodeTypes>>(&data)
                            .expect(&format!("Unable to load function data from {}", ele));

                    if !json.nodes.is_empty() {
                        subset_loaded_data.push(Some(json))
                    } else {
                        subset_loaded_data.push(None)
                    }
                }

                subset_loaded_data.retain(|c| c.is_some());

                debug!("Starting to deduplicate the corpus - {}", idx);
                Self::dedup_corpus(&mut subset_loaded_data, &mut fp_subset.to_vec());
                let subset_loaded_data: Vec<NetworkxDiGraph<_>> =
                    subset_loaded_data.into_iter().flatten().collect();
                debug!("Starting to save - {}", idx);
                self.save_corpus(subset_loaded_data, fp_subset);
                debug!("File processing complete - {}", idx);
            });
    }
    pub fn save_corpus(
        &self,
        subset_loaded_data: Vec<NetworkxDiGraph<CallGraphNodeTypes>>,
        fp_subset: &[String],
    ) {
        subset_loaded_data
            .iter()
            .zip(fp_subset.iter())
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
                serde_json::to_writer(
                    &File::create(fixed_path).expect("Failed to create writer"),
                    &data_ele,
                )
                .expect("Unable to write JSON");
            });
    }
}

mod tests {

    #[test]
    fn test_binkit_binary_extraction() {
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"which-2.21_gcc-9.4.0_arm_32_O2_which_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json
".to_string()
            ),
            "which"
        );
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"recutils-1.9_gcc-11.2.0_mips_64_O3_recins_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json
".to_string()
            ),
            "recins"
        );
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"recutils-1.9_gcc-11.2.0_mips_64_O3_recsel_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json
".to_string(),
            ),
            "recsel",
        );
    }

    #[test]
    fn test_cisco_binary_extraction() {
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"arm64-clang-9-Os_curl_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json".to_string()
            ),
            "curl"
        );
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"x86-clang-9-Os_libcrypto.so.3_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json
".to_string()
            ),
            "libcrypto.so.3"
        );
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"x86-gcc-9-O3_unrar_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json
".to_string(),
            ),
            "unrar",
        );
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"/random/path/before/x86-gcc-9-O3_unrar_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json
".to_string(),
            ),
            "unrar",
        );
    }
}
