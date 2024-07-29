use crate::afij::AFIJFunctionInfo;
use crate::agfj::TikNibFuncFeatures;
use crate::errors::FileLoadError;
use crate::files::{AFIJFile, TikNibFuncMetaFile};
use crate::utils::{get_json_paths_from_dir, get_save_file_path};
use anyhow::{anyhow, Error};
use ordered_float::OrderedFloat;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use serde::{Deserialize, Serialize};
use std::fs::read_to_string;
use std::path::{Path, PathBuf};
use std::process::exit;

#[derive(Debug)]
pub enum ComboTypes {
    FinfoTikib,
}

impl ComboTypes {
    pub fn new(combo_type: &str) -> ComboTypes {
        match combo_type {
            "finfo+tiknib" => ComboTypes::FinfoTikib,
            _ => unreachable!("Unable to determine combo type"),
        }
    }
    pub fn to_combo_file_types(&self) -> Result<(ComboFileTypes, ComboFileTypes), Error> {
        match self {
            ComboTypes::FinfoTikib => Ok((
                ComboFileTypes::AFIJFunctionInfo,
                ComboFileTypes::TikNibFuncFeatures,
            )),
        }
    }
}

#[derive(Debug)]
pub enum ComboFileTypes {
    AFIJFunctionInfo,
    TikNibFuncFeatures,
}
#[derive(Debug)]
pub struct ComboJob {
    pub combo_type: ComboTypes,
    pub input_path: PathBuf,
    pub output_path: PathBuf,
}

impl ComboJob {
    pub fn new(combo_type: &str, input_path: &Path, output_path: &Path) -> Result<ComboJob, Error> {
        let combo_type = ComboTypes::new(combo_type);
        let combo_file_types = combo_type.to_combo_file_types();

        if combo_file_types.is_ok() {
            Ok(ComboJob {
                combo_type,
                input_path: input_path.to_path_buf(),
                output_path: output_path.to_path_buf(),
            })
        } else {
            Err(anyhow!("Unable to create ComboJob"))
        }
    }

    pub fn process_finfo_tiknib(self) {
        let mut finfo_paths = get_json_paths_from_dir(&self.input_path, Some("_finfo".to_string()));
        let mut tiknib_paths =
            get_json_paths_from_dir(&self.input_path, Some("cfg-tiknib".to_string()));

        finfo_paths.sort();
        tiknib_paths.sort();

        if finfo_paths.len() != tiknib_paths.len() {
            error!("Mismatch in number of files found. Exiting.");
            exit(1)
        }

        let joint_par_iter = finfo_paths.par_iter().zip(tiknib_paths.par_iter());
        joint_par_iter.for_each(|(finfo, tiknib)| {
            info!("{} -> {}", finfo, tiknib);

            let mut finfo_obj: AFIJFile = AFIJFile {
                filename: finfo.parse().unwrap(),
                function_info: None,
                output_path: self.output_path.clone(),
            };
            let finfo_load_ret = finfo_obj.load_and_deserialize();

            let mut tiknib_obj: TikNibFuncMetaFile = TikNibFuncMetaFile {
                filename: tiknib.parse().unwrap(),
                function_info: None,
                output_path: self.output_path.clone(),
            };
            let tiknib_load_ret = tiknib_obj.load_and_deserialize();

            let mut generated_combos = Vec::new();

            if finfo_load_ret.is_ok() & tiknib_load_ret.is_ok() {
                let finfo_obj_functions = finfo_obj.function_info.unwrap();
                let tiknib_obj_functions = tiknib_obj.function_info.unwrap();

                for (finfo, tiknib) in finfo_obj_functions
                    .into_iter()
                    .zip(tiknib_obj_functions.into_iter())
                {
                    let combined = FinfoTiknib::from((finfo, tiknib.features));
                    generated_combos.push(combined);
                }
            } else {
                error!("Failed to load and deserialize files");
            }
            // Save combined object to JSON file
            let save_path = get_save_file_path(
                &finfo_obj.filename.to_owned(),
                &self.output_path,
                Some(".json".to_string()),
                Some("tiknib".to_string()),
                None,
            );
            debug!("Save Path: {:?}", save_path);

            let save_file = std::fs::File::create(save_path).expect("Unable to create file");
            serde_json::to_writer(&save_file, &generated_combos).expect("Unable to write to file");
        });
    }
    /*
    To be implemented
    pub fn process(&self) {}

    fn combine_finfo_tiknib(&self) {}
     */
}

#[derive(Default, Hash, PartialEq, Clone, Debug, Deserialize, Serialize)]
pub struct FinfoTiknib {
    pub name: String,
    pub edges: i64,
    pub indegree: i64,
    pub outdegree: i64,
    pub nlocals: i64,
    pub nargs: i64,
    pub avg_arithshift: OrderedFloat<f32>,
    pub avg_compare: OrderedFloat<f32>,
    pub avg_ctransfer: OrderedFloat<f32>,
    pub avg_ctransfercond: OrderedFloat<f32>,
    pub avg_dtransfer: OrderedFloat<f32>,
    pub avg_float: OrderedFloat<f32>,
    pub avg_total: OrderedFloat<f32>,
    // Sum
    pub sum_arithshift: OrderedFloat<f32>,
    pub sum_compare: OrderedFloat<f32>,
    pub sum_ctransfer: OrderedFloat<f32>,
    pub sum_ctransfercond: OrderedFloat<f32>,
    pub sum_dtransfer: OrderedFloat<f32>,
    pub sum_float: OrderedFloat<f32>,
    pub sum_total: OrderedFloat<f32>,
}

impl FinfoTiknib {
    pub fn save_to_json(&self, path: &PathBuf) -> Result<(), Error> {
        let json = serde_json::to_string(&self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct FinfoTiknibFile {
    pub filename: PathBuf,
    pub function_info: Option<Vec<FinfoTiknib>>,
    pub output_path: PathBuf,
}

impl FinfoTiknibFile {
    pub fn load_and_deserialize(&mut self) -> Result<(), FileLoadError> {
        let data = read_to_string(&self.filename)?;

        #[allow(clippy::expect_fun_call)]
        // Kept in to ensure that the JSON decode error message is printed alongside the filename
        let json: Vec<FinfoTiknib> = serde_json::from_str(&data)?;

        self.function_info = Some(json);
        Ok(())
    }
}

impl From<(AFIJFunctionInfo, TikNibFuncFeatures)> for FinfoTiknib {
    fn from(value: (AFIJFunctionInfo, TikNibFuncFeatures)) -> Self {
        FinfoTiknib {
            name: value.0.name,
            edges: value.0.edges,
            indegree: value.0.indegree.unwrap_or(0),
            outdegree: value.0.outdegree.unwrap_or(0),
            nlocals: value.0.nlocals.unwrap_or(0),
            nargs: value.0.nargs.unwrap_or(0),
            avg_arithshift: value.1.avg_arithshift,
            avg_compare: value.1.avg_compare,
            avg_ctransfer: value.1.avg_ctransfer,
            avg_ctransfercond: value.1.avg_ctransfercond,
            avg_dtransfer: value.1.avg_dtransfer,
            avg_float: value.1.avg_float,
            avg_total: value.1.avg_total,
            sum_arithshift: value.1.sum_arithshift,
            sum_compare: value.1.sum_compare,
            sum_ctransfer: value.1.sum_ctransfer,
            sum_ctransfercond: value.1.sum_ctransfercond,
            sum_dtransfer: value.1.sum_dtransfer,
            sum_float: value.1.sum_float,
            sum_total: value.1.sum_total,
        }
    }
}
