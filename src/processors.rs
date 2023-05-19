/*
ALOT OF THIS IS DEPRECATED - NEED TO WORK OUT WHAT TO KEEP AND WHAT TO REMOVE
 */
use crate::bb::{FeatureType, InstructionMode};
use crate::files::AGFJFile;
#[cfg(feature = "inference")]
use crate::inference::InferenceJob;
use serde::{Deserialize, Serialize};
use std::fs::write;
use std::path::Path;
#[cfg(feature = "inference")]
use std::process::exit;
use std::string::String;
#[cfg(feature = "inference")]
use std::sync::Arc;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(transparent)]
struct GroupOfCases {
    items: Vec<SingleCase>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct SingleCase {
    addr: u64,
    jump: u64,
    value: u8,
}

#[derive(Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[serde(transparent)]
struct EdgesList {
    edge_set: Vec<EdgePair>,
}

#[derive(Deserialize, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct EdgePair {
    src: u16,
    dest: u16,
    wt: u16,
}

#[allow(clippy::too_many_arguments)]
#[cfg(feature = "inference")]
pub fn agfj_graph_embedded_feats(
    path: &str,
    min_blocks: &u16,
    output_path: &str,
    feature_type: FeatureType,
    tokeniser_fp: &Option<String>,
    model_fp: &Option<String>,
    mean_pool: &bool,
    embed_dim: &Option<i64>,
) {
    let file = AGFJFile {
        functions: None,
        filename: path.to_owned(),
        output_path: output_path.to_string(),
        min_blocks: *min_blocks,
        feature_type: Some(feature_type),
        architecture: None,
    };

    // TODO: Add logic here that creates an inference job differently depending on if tokeniser_fp and model_fp
    // are present either together or on their own
    if (tokeniser_fp.is_some() && model_fp.is_none())
        || (tokeniser_fp.is_none() && model_fp.is_some())
    {
        println!("Unable to create an inference job without both tokeniser fp and model fp! ")
    }
    let inference_job: Option<Arc<InferenceJob>> = if tokeniser_fp.is_some() || model_fp.is_some() {
        Some(Arc::new(
            InferenceJob::new(
                tokeniser_fp.as_ref().unwrap(),
                model_fp,
                *mean_pool,
                embed_dim,
            )
            .unwrap(),
        ))
    } else {
        None
    };

    file.parallel_embedded_cfg_gen(inference_job)
}

pub fn agfj_graph_statistical_features(
    path: &str,
    min_blocks: &u16,
    output_path: &str,
    feature_type: FeatureType,
) {
    let mut file = AGFJFile {
        functions: None,
        filename: path.to_owned(),
        output_path: output_path.to_string(),
        min_blocks: *min_blocks,
        feature_type: Some(feature_type),
        architecture: None,
    };

    file.load_and_deserialize()
        .expect("Unable to load and deserialise file.");
    file.paralell_attributed_cfg_gen()
}

pub fn generate_random_walks(
    path: &str,
    mode: InstructionMode,
    min_blocks: &u16,
    output_path: &str,
) {
    let file = AGFJFile {
        functions: None,
        filename: path.to_owned(),
        output_path: output_path.to_string(),
        min_blocks: *min_blocks,
        feature_type: None,
        architecture: None,
    };

    let walks = if mode == InstructionMode::ESIL {
        file.generate_random_bb_walk(true)
    } else if mode == InstructionMode::Disasm {
        file.generate_random_bb_walk(false)
    } else {
        unreachable!()
    };

    let file_name = Path::new(path).file_stem().unwrap();

    let full_output_path = format!(
        "{}/{}-{:?}.txt",
        output_path.strip_suffix('/').unwrap_or(output_path),
        String::from(file_name.to_str().unwrap()),
        mode
    );
    write(full_output_path, walks.join("\n")).expect("");
}

pub fn generate_esil_func_strings(path: &str, min_blocks: &u16, output_path: &str) {
    let file = AGFJFile {
        functions: None,
        filename: path.to_owned(),
        output_path: output_path.to_string(),
        min_blocks: *min_blocks,
        feature_type: None,
        architecture: None,
    };

    file.generate_esil_func_strings();
}

pub fn generate_disasm_func_string(
    path: &str,
    min_blocks: &u16,
    output_path: &str,
    reg_norm: bool,
) {
    let file = AGFJFile {
        functions: None,
        filename: path.to_owned(),
        output_path: output_path.to_string(),
        min_blocks: *min_blocks,
        feature_type: None,
        architecture: None,
    };
    file.generate_disasm_func_strings(reg_norm);
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_example_in_graph_rs() {
        assert_eq!(1, 1);
    }
}
