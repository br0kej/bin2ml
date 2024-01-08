use crate::networkx::{CallGraphFuncWithMetadata, CallGraphNodeTypes, NetworkxDiGraph};
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

/// Struct and Impl for de-duplicating Call Graph Corpus's
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

        let output_path = if output_path.ends_with("/") {
            output_path.to_owned()
        } else {
            output_path.to_owned() + &*"/".to_string()
        };

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

    fn extract_binary_from_fps(&self) -> Vec<String> {
        let mut fp_binaries = Vec::new();
        // Process the file paths to get the associated binary of each path
        info!("Processing Filepaths to get binaries");
        for file in &self.filepaths {
            let binary = match self.filepath_format.as_str() {
                "cisco" => Self::get_binary_name_cisco(file),
                "binkit" => Self::get_binary_name_binkit(file),
                "trex" => Self::get_binary_name_binkit(file),
                _ => unreachable!(),
            };
            trace!("Extracted Binary Name: {:?} from {:?}", binary, file);
            fp_binaries.push(binary)
        }
        fp_binaries
    }

    fn get_unique_binary_fps(&self, fp_binaries: Vec<String>) -> Vec<Vec<String>> {
        // Generate binary specific filepath vectors
        let unique_binaries: Vec<_> = fp_binaries.iter().unique().collect();
        let mut unique_binaries_fps: Vec<Vec<String>> = vec![Vec::new(); unique_binaries.len()];

        for (file, binary) in self.filepaths.iter().zip(fp_binaries.iter()) {
            unique_binaries_fps[unique_binaries.iter().position(|&x| x == binary).unwrap()]
                .push(file.clone());
        }

        unique_binaries_fps
    }

    fn load_subset(
        &self,
        fp_subset: &Vec<String>,
    ) -> Vec<Option<NetworkxDiGraph<CallGraphFuncWithMetadata>>> {
        let mut subset_loaded_data = Vec::new();
        for ele in fp_subset.iter() {
            let data = read_to_string(ele).expect(&format!("Unable to read file - {:?}", ele));
            let json: NetworkxDiGraph<CallGraphFuncWithMetadata> =
                serde_json::from_str::<NetworkxDiGraph<CallGraphFuncWithMetadata>>(&data)
                    .expect(&format!("Unable to load function data from {}", ele));
            debug!("{:?}", json);

            if !json.nodes.is_empty() {
                subset_loaded_data.push(Some(json))
            } else {
                subset_loaded_data.push(None)
            }
        }
        subset_loaded_data
    }

    pub fn process_corpus(self) {
        let fp_binaries = self.extract_binary_from_fps();

        // Generate binary specific filepath vectors
        let mut unique_binaries_fps = self.get_unique_binary_fps(fp_binaries);

        info!("Loading the filepaths");
        unique_binaries_fps
            .par_iter_mut()
            .progress()
            .enumerate()
            .for_each(|(idx, fp_subset)| {
                let mut subset_loaded_data: Vec<
                    Option<NetworkxDiGraph<CallGraphFuncWithMetadata>>,
                > = self.load_subset(fp_subset);

                debug!("Starting to deduplicate the corpus - {}", idx);
                Self::dedup_corpus(&mut subset_loaded_data, fp_subset);
                let subset_loaded_data: Vec<NetworkxDiGraph<_>> =
                    subset_loaded_data.into_iter().flatten().collect();
                debug!("Starting to save - {}", idx);
                self.save_corpus(subset_loaded_data, fp_subset);
                debug!("File processing complete - {}", idx);
            });
    }
    pub fn save_corpus(
        &self,
        subset_loaded_data: Vec<NetworkxDiGraph<CallGraphFuncWithMetadata>>,
        fp_subset: &mut Vec<String>,
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
                trace!("Fixed Path (First Pass): {:?}", fixed_path);
                let fixed_path = fixed_path
                    .iter()
                    .map(|c| c.as_os_str().to_string_lossy().to_string())
                    .rev()
                    .collect::<Vec<String>>();
                trace!("Fixed Path (Second Pass): {:?}", fixed_path);
                let dirs = format!("{}{}", self.output_path, fixed_path[0]);
                fs::create_dir_all(&dirs).expect("Failed to create output directory!");

                let fixed_path = format!("{}/{}", dirs, fixed_path[1]);
                trace!("Fixed Path (Final Pass): {:?}", fixed_path);
                serde_json::to_writer(
                    &File::create(fixed_path).expect("Failed to create writer"),
                    &data_ele,
                )
                .expect("Unable to write JSON");
            });
    }
}

mod tests {
    use super::*;
    use crate::dedup::CGCorpus;
    use itertools::assert_equal;
    // Test Dedup on typed CG's
    #[test]
    fn test_cg_corpus_gen() {
        // CG Corpus Generation
        let corpus = CGCorpus::new(
            &"test-files/cg_dedup/to_dedup".to_string(),
            &"test-files/cg_dedup/deduped".to_string(),
            &"cisco".to_string(),
        );
        assert_eq!(corpus.as_ref().unwrap().filepaths.len(), 12);
        assert_eq!(
            corpus.as_ref().unwrap().output_path,
            "test-files/cg_dedup/deduped/".to_string()
        );
        assert_eq!(
            corpus.as_ref().unwrap().filepath_format,
            "cisco".to_string()
        );

        let corpus = CGCorpus::new(
            &"test-files/cg_dedup/to_dedup".to_string(),
            &"test-files/cg_dedup/deduped/".to_string(),
            &"cisco".to_string(),
        );
        assert_eq!(corpus.as_ref().unwrap().filepaths.len(), 12);
        assert_eq!(
            corpus.as_ref().unwrap().output_path,
            "test-files/cg_dedup/deduped/".to_string()
        );
        assert_eq!(
            corpus.as_ref().unwrap().filepath_format,
            "cisco".to_string()
        );
    }

    #[test]
    fn test_extract_binary_from_fps() {
        let corpus = CGCorpus::new(
            &"test-files/cg_dedup/to_dedup".to_string(),
            &"test-files/cg_dedup/deduped".to_string(),
            &"cisco".to_string(),
        );

        let fp_binaries = corpus.unwrap().extract_binary_from_fps();
        assert_eq!(fp_binaries.len(), 12);
        assert_eq!(
            fp_binaries,
            vec![
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin".to_string(),
                "testbin2".to_string(),
                "testbin2".to_string(),
                "testbin2".to_string(),
                "testbin2".to_string(),
            ]
        )
    }

    #[test]
    fn test_get_unique_binary_fps() {
        let corpus = CGCorpus::new(
            &"test-files/cg_dedup/to_dedup".to_string(),
            &"test-files/cg_dedup/deduped".to_string(),
            &"cisco".to_string(),
        )
        .unwrap();
        let fp_binaries = corpus.extract_binary_from_fps();
        let unique_binary_fps = corpus.get_unique_binary_fps(fp_binaries);

        assert_eq!(unique_binary_fps.len(), 2);
        assert_eq!(unique_binary_fps[0].len(), 8);
        assert_eq!(unique_binary_fps[1].len(), 4);
    }

    #[test]
    fn test_processing_unique_binary_collection() {
        let corpus = CGCorpus::new(
            &"test-files/cg_dedup/to_dedup".to_string(),
            &"test-files/cg_dedup/deduped".to_string(),
            &"cisco".to_string(),
        )
        .unwrap();
        let fp_binaries = corpus.extract_binary_from_fps();
        let unique_binary_fps = corpus.get_unique_binary_fps(fp_binaries);

        // Load the first collection which has dups
        let mut subset_loaded = corpus.load_subset(&unique_binary_fps[0]);
        assert_eq!(subset_loaded.len(), 8);
        subset_loaded.retain(|c| c.is_some());
        assert_eq!(subset_loaded.len(), 8);
    }

    #[test]
    fn test_dedup_binary_subset() {
        let corpus = CGCorpus::new(
            &"test-files/cg_dedup/to_dedup".to_string(),
            &"test-files/cg_dedup/deduped".to_string(),
            &"cisco".to_string(),
        )
        .unwrap();
        let fp_binaries = corpus.extract_binary_from_fps();
        let mut unique_binary_fps = corpus.get_unique_binary_fps(fp_binaries);

        // Load the first collection which has dups
        let mut subset_loaded = corpus.load_subset(&unique_binary_fps[0]);
        subset_loaded.retain(|c| c.is_some());

        // Prior to dedup
        assert_eq!(subset_loaded.len(), 8);
        CGCorpus::dedup_corpus(&mut subset_loaded, &mut unique_binary_fps[0]);

        // Subset
        assert_eq!(subset_loaded.len(), 4);

        // Filepaths
        assert_eq!(unique_binary_fps[0].len(), 4);

        // Check first node - should be function name
        for (loaded_ele, filepath) in subset_loaded.iter().zip(unique_binary_fps[0].iter()) {
            let loaded_func_name = &loaded_ele.clone().unwrap().nodes[0].func_name;
            let filepath_func_name: Vec<_> = Path::new(filepath)
                .components()
                .rev()
                .take(1)
                .collect::<Vec<_>>();

            let filepath_func_name = filepath_func_name[0]
                .as_os_str()
                .to_string_lossy()
                .to_string();

            let filepath_func_name = filepath_func_name.split("-").next().unwrap();

            assert_eq!(loaded_func_name.to_owned(), filepath_func_name)
        }
        let subset_loaded: Vec<NetworkxDiGraph<_>> = subset_loaded.into_iter().flatten().collect();

        // Save corpus!
        corpus.save_corpus(subset_loaded, &mut unique_binary_fps[0]);

        // Check the files saved!
        for file in WalkDir::new(&corpus.output_path)
            .into_iter()
            .filter_map(|file| file.ok())
        {
            if file.path().to_string_lossy().ends_with(".json") {
                let data = read_to_string(file.path())
                    .expect(&format!("Unable to read file - {:?}", file));
                let json: NetworkxDiGraph<CallGraphFuncWithMetadata> =
                    serde_json::from_str::<NetworkxDiGraph<CallGraphFuncWithMetadata>>(&data)
                        .expect(&format!("Unable to load function data from {:?}", file));

                let filepath_func_name: Vec<_> = Path::new(file.file_name())
                    .components()
                    .rev()
                    .take(1)
                    .collect::<Vec<_>>();

                let filepath_func_name = filepath_func_name[0]
                    .as_os_str()
                    .to_string_lossy()
                    .to_string();

                let filepath_func_name = filepath_func_name.split("-").next().unwrap();

                assert_eq!(json.nodes[0].func_name, filepath_func_name)
            }
        }

        // clean up
        fs::remove_dir_all(&corpus.output_path).expect("Unable to remove directory!");
    }

    // Test binary name extraction
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

    #[test]
    fn test_trex_binary_extraction() {
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"arm-32_binutils-2.34-O0_elfedit_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json".to_string()
            ),
            "elfedit"
        );

        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"arm-32_binutils-2.34-O0_objdump_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json".to_string()
            ),
            "objdump"  
        );
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"arm-32_binutils-2.34-O0_nm-new_cg-onehopcgcallers-meta/sym.dummy-func-onehopcgcallers-meta.json".to_string()
            ),
            "nm-new"
        );
        // __ for c++ bins that sometimes crop up
        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(
                &"arm-32_binutils-2.34-O0_nm-new_cg-onehopcgcallers-meta/sym.dummy___func__-onehopcgcallers-meta.json".to_string()
            ),
            "nm-new"
        );

        assert_eq!(
            crate::dedup::CGCorpus::get_binary_name_binkit(&"fast-disk/Dataset-2/cgs/x86-32_coreutils-8.32-O1_stat_cg-onehopcgcallers-meta/main-onehopcgcallers-meta.json".to_string()),
            "stat"
        );

        assert_eq!(crate::dedup::CGCorpus::get_binary_name_binkit(&"/fast-disk/processed_datasets/Dataset-2/arm-32_binutils-2.34-O0_addr2line_cg-onehopcgcallers-meta/sym.adjust_relative_path-onehopcgcallers-meta.json".to_string()),
        "addr2line")
    }
}
