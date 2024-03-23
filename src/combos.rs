use std::fs::read_to_string;
use crate::afij::AFIJFunctionInfo;
use crate::agfj::{TikNibFunc, TikNibFuncFeatures};
use anyhow::{anyhow, Error};
use ordered_float::OrderedFloat;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::errors::FileLoadError;

#[derive(Debug)]
enum ComboTypes {
    FinfoTikib,
}

impl ComboTypes {
    pub fn new(combo_type: &String) -> ComboTypes {
        match combo_type.as_str() {
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
enum ComboFileTypes {
    AFIJFunctionInfo,
    TikNibFuncFeatures,
}
#[derive(Debug)]
pub struct ComboJob {
    pub combo_type: ComboTypes,
    file_type_one: ComboFileTypes,
    file_type_two: ComboFileTypes,
    pub input_path: PathBuf,
    pub output_path: PathBuf,
}

impl ComboJob {
    pub fn new(
        combo_type: &String,
        input_path: &PathBuf,
        output_path: &PathBuf,
    ) -> Result<ComboJob, Error> {
        let combo_type = ComboTypes::new(combo_type);
        let combo_file_types = combo_type.to_combo_file_types();

        if combo_file_types.is_ok() {
            let combo_file_types = combo_file_types.unwrap();
            Ok(ComboJob {
                combo_type,
                file_type_one: combo_file_types.0,
                file_type_two: combo_file_types.1,
                input_path: input_path.clone(),
                output_path: output_path.clone(),
            })
        } else {
            Err(anyhow!("Unable to create ComboJob"))
        }
    }

    pub fn process(&self) {}

    fn combine_finfo_tiknib(&self) {}
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
