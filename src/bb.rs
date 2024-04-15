use crate::consts::*;
#[cfg(feature = "inference")]
use crate::inference::InferenceJob;
use crate::normalisation::{normalise_disasm_simple, normalise_esil_simple};
use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_json::Value;
use serde_with::{serde_as, DefaultOnError};
use std::collections::HashMap;
use std::string::String;
#[cfg(feature = "inference")]
use std::sync::Arc;
#[cfg(feature = "inference")]
use tch::Tensor;

#[derive(Serialize, Deserialize, Debug, PartialEq, Copy, Clone)]
pub enum FeatureType {
    Gemini,
    DiscovRE,
    DGIS,
    Tiknib,
    ModelEmbedded,
    Encoded,
    Invalid,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Copy)]
pub enum InstructionMode {
    ESIL,
    Disasm,
    Invalid,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SwitchOpCase {
    pub jump: i64,
    pub offset: i64,
    #[serde(deserialize_with = "deserialize_string_from_number")]
    // This will make it challenging to use downstream but has been
    // added because sometimes it is a VERY large int (bigger than i64).
    // This ends up breaking the deserialization and makes the processing
    // bomb out
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct SwitchOp {
    pub cases: Vec<SwitchOpCase>,
    pub defval: u16,
    pub maxval: u16,
    pub minval: u16,
    pub offset: u64,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Op {
    pub bytes: Option<String>,
    pub comment: Option<String>,
    pub disasm: Option<String>,
    pub esil: Option<String>,
    pub family: Option<String>,
    pub fcn_addr: Option<u64>,
    pub fcn_last: Option<u64>,
    pub flags: Option<Vec<String>>,
    pub offset: u64,
    pub opcode: Option<String>,
    pub ptr: Option<u128>,
    pub refptr: Option<u128>,
    pub refs: Option<Vec<HashMap<String, Value>>>,
    pub reloc: Option<bool>,
    pub size: Option<u64>,
    pub r#type: String,
    pub type2_num: Option<u64>,
    pub type_num: Option<u64>,
    pub xrefs: Option<Vec<HashMap<String, Value>>>,
    pub val: Option<u64>,
}

// Function to set offset, jump and fail to default values
fn return_minus_one() -> i64 {
    -1
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct ACFJBlock {
    #[serde(default = "return_minus_one")]
    pub offset: i64,
    #[serde(default = "return_minus_one")]
    #[serde_as(deserialize_as = "DefaultOnError")]
    // This has been added to eliminate an error where
    // the jump address from x86-64 binaries is larger than
    // an i64.
    pub jump: i64,
    #[serde(default = "return_minus_one")]
    pub fail: i64,
    pub ops: Vec<Op>,
    pub size: Option<i64>,
    pub switchop: Option<SwitchOp>,
}

// Data Transfer + Misc have been removed.
// Paper shows its a weak feature
#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Debug, Default)]
pub struct TikNibFeaturesBB {
    pub arithshift: f32,
    pub compare: f32,
    pub ctransfer: f32,
    pub ctransfercond: f32,
    pub dtransfer: f32,
    pub float: f32,
    pub total: f32,
}

impl TikNibFeaturesBB {
    pub fn to_vec(self) -> Vec<f64> {
        let mut feature_vec = vec![0.0; 7];
        feature_vec[0] = self.arithshift as f64;
        feature_vec[1] = self.compare as f64;
        feature_vec[2] = self.ctransfer as f64;
        feature_vec[3] = self.ctransfercond as f64;
        feature_vec[4] = self.dtransfer as f64;
        feature_vec[5] = self.float as f64;
        feature_vec[6] = self.total as f64;

        feature_vec
    }
}
impl From<&Vec<f64>> for TikNibFeaturesBB {
    fn from(src: &Vec<f64>) -> TikNibFeaturesBB {
        TikNibFeaturesBB {
            arithshift: src[0] as f32,
            compare: src[1] as f32,
            ctransfer: src[2] as f32,
            ctransfercond: src[3] as f32,
            dtransfer: src[4] as f32,
            float: src[5] as f32,
            total: src[6] as f32,
        }
    }
}
impl FeatureType {
    // Returns the corresponding feature map given a provided FeatureType
    // These feature maps are used to provide the functionality that handles
    // writing the output graphs to Networkx compatible JSON with
    // node attribute names.
    pub fn get_feature_map(self) -> Vec<&'static str> {
        match self {
            FeatureType::Gemini => GEMINI_FEATURE_MAP.to_vec(),
            FeatureType::DiscovRE => DISCOVRE_FEATURE_MAP.to_vec(),
            FeatureType::DGIS => DGIS_FEATURE_MAP.to_vec(),
            _ => unreachable!(),
        }
    }
}

impl ACFJBlock {
    // Generates integer encodings of a basic blocks ESIL instructions
    //
    // This is to provide a means of conducting the extraction and tokenisation
    // of ESIL instructions within Rust but then load the features in Python
    // to conduct inference and convert them into embeddings.
    #[cfg(feature = "inference")]
    pub fn generate_bb_encoding_esil(
        &self,
        feature_vecs: &mut Vec<Vec<Vec<f64>>>,
        inference_job: Arc<InferenceJob>,
    ) {
        let mut basic_block: Vec<_> = Vec::new();
        let normalised_esil = self.get_esil_bb();
        for normed_esil_ins in normalised_esil {
            let embedded_esil: Vec<i32> = inference_job.encode(normed_esil_ins.as_str());
            let casted_esil: Vec<f64> = embedded_esil.iter().map(|&val| val as f64).collect();
            basic_block.push(casted_esil)
        }
        feature_vecs.push(basic_block)
    }
    #[cfg(feature = "inference")]
    // Generates a basic block ESIL embedding using a learning model
    pub fn generate_bb_embedding_esil(
        &self,
        feature_vecs: &mut Vec<Vec<f64>>,
        inference_job: Arc<InferenceJob>,
    ) {
        let mut feature_tensor: Tensor = Tensor::empty(
            &[1, 1, inference_job.embed_dim],
            (tch::Kind::Float, inference_job.device),
        );
        for ins in self.ops.iter() {
            if ins.r#type != "invalid" && ins.esil.is_some() {
                let embedded_esil: Tensor =
                    inference_job.embed(ins.esil.as_ref().unwrap().as_str());
                feature_tensor = Tensor::cat(&[&feature_tensor, &embedded_esil], 1);
            }
        }
        let pooled_tensor = feature_tensor.mean_dim(Some([1].as_slice()), true, tch::Kind::Double);

        let feature_vector: Vec<f64> = Vec::<f64>::from(pooled_tensor);
        feature_vecs.push(feature_vector);
    }

    // ATTRIBUTE CFG FEATURE GENERATION - COUNTS

    // Helper function to select which feature generation function to
    // execute based on the provided FeatureType
    pub fn generate_bb_feature_vec(
        &self,
        feature_vecs: &mut Vec<Vec<f64>>,
        feature_type: FeatureType,
        architecture: &String,
    ) {
        let feature_vector: Vec<f64> = match feature_type {
            FeatureType::DiscovRE => self.gemini_features(architecture, true),
            FeatureType::Gemini => self.gemini_features(architecture, false),
            FeatureType::DGIS => self.dgis_features(architecture),
            FeatureType::Tiknib => self.get_tiknib_features_vec(architecture),
            _ => unreachable!(),
        };

        if feature_vector.is_empty() {
            println!("Empty feature vector. This means that the feature type is wrong!")
        } else {
            feature_vecs.push(feature_vector);
        }
    }

    // Generates the features from the Gemini paper
    //
    // Setting reduced = True is equivalent of generating the basic block
    // features from the DISCOVRE paper (Eshweiler et al (2016))
    //
    // Note: The Betweenness feature used in Gemini is calculated down stream using
    // Networkx
    //pub fn gemini_features(&self, architecture: &String, reduced: bool) -> Vec<f64> {
    pub fn gemini_features(&self, architecture: &String, reduced: bool) -> Vec<f64> {
        let n_features = if reduced { 6 } else { 7 };

        let mut feature_vector: Vec<f64> = vec![0.0; n_features];

        for ins in self.ops.iter() {
            if ins.r#type != "invalid" {
                let opcode = ins
                    .opcode
                    .as_ref()
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap();

                if architecture == "ARM" {
                    if ARM_CALL.contains(&opcode) {
                        feature_vector[0] += 1. // Number of Calls
                    } else if ARM_TRANSFER.contains(&opcode) {
                        feature_vector[1] += 1. // Number of Transfer Instructions
                    } else if ARM_ARITHMETIC.contains(&opcode) {
                        feature_vector[2] += 1. // No. of Arithmetic Instructions
                    }
                } else if architecture == "X86" {
                    if X86_CALL.contains(&opcode) {
                        feature_vector[0] += 1. // Number of Calls
                    } else if X86_TRANSFER.contains(&opcode) {
                        feature_vector[1] += 1. // Number of Transfer Instructions
                    } else if X86_ARITHMETIC.contains(&opcode) {
                        feature_vector[2] += 1. // No. of Arithmetic Instructions
                    }
                } else if architecture == "MIPS" {
                    if MIPS_CALL.contains(&opcode) {
                        feature_vector[0] += 1. // Number of Calls
                    } else if MIPS_TRANSFER.contains(&opcode) {
                        feature_vector[1] += 1. // Number of Transfer Instructions
                    } else if MIPS_ARITHMETIC.contains(&opcode) {
                        feature_vector[2] += 1. // No. of Arithmetic Instructions
                    }
                } else {
                    unreachable!(
                        "Invalid Architecture - This shouldn't happen! Got {}",
                        architecture
                    )
                }

                feature_vector[3] += 1.; // No. of Insutrctions

                if ins.disasm.as_ref().unwrap().contains(", 0x") {
                    feature_vector[4] += 1. // Numeric Constants
                }

                if ins.disasm.as_ref().unwrap().contains(" str.") {
                    feature_vector[5] += 1. // String Constants
                }
            }

            if !reduced {
                feature_vector[6] = self.get_no_offspring();
            }
        }
        feature_vector
    }

    // Implements the basic block feature extraction for DGIS - Liu et al (2022)
    // Dual-Granularity Interactive Semantic Learning Based Vulnerability Detection
    // Approach for Cross-Platform Binaries.
    // The feature list is taken from Table 1 within the paper
    pub fn dgis_features(&self, architecture: &String) -> Vec<f64> {
        let mut feature_vector: Vec<f64> = vec![0.0; 8];
        for ins in self.ops.iter() {
            if ins.r#type != "invalid" {
                let opcode = ins
                    .opcode
                    .as_ref()
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap();
                if architecture == "ARM" {
                    if ARM_STACK.contains(&opcode) {
                        feature_vector[0] += 1. // No. of Stack Operations
                    } else if ARM_ARITHMETIC.contains(&opcode) {
                        feature_vector[1] += 1. // No. of Arithmetic Instructions
                    } else if ARM_LOGIC.contains(&opcode) {
                        feature_vector[2] += 1. // No. of Logical Instructions
                    } else if ARM_COMPARE.contains(&opcode) {
                        feature_vector[3] += 1. // No. of comparative instructions
                    } else if ARM_CALL.contains(&opcode)
                        && ins.disasm.as_ref().unwrap().contains("imp")
                    {
                        feature_vector[4] += 1. // No. of library function calls
                    } else if ARM_UNCOND.contains(&opcode) {
                        feature_vector[5] += 1. // No. of unconditional jumps
                    } else if ARM_COND.contains(&opcode) {
                        feature_vector[6] += 1. // No. of conditional jumps
                    } else {
                        feature_vector[7] += 1. // No. of generic instructions (mov, lea)
                    }
                } else if architecture == "X86" {
                    if X86_STACK.contains(&opcode) {
                        feature_vector[0] += 1. // No. of Stack Operations
                    } else if X86_ARITHMETIC.contains(&opcode) {
                        feature_vector[1] += 1. // No. of Arithmetic Instructions
                    } else if X86_LOGIC.contains(&opcode) {
                        feature_vector[2] += 1. // No. of Logical Instructions
                    } else if X86_COMPARE.contains(&opcode) {
                        feature_vector[3] += 1. // No. of comparative instructions
                    } else if X86_CALL.contains(&opcode)
                        && ins.disasm.as_ref().unwrap().contains("imp")
                    {
                        feature_vector[4] += 1. // No. of library function calls
                    } else if X86_UNCOND.contains(&opcode) {
                        feature_vector[5] += 1. // No. of unconditional jumps
                    } else if X86_COND.contains(&opcode) {
                        feature_vector[6] += 1. // No. of conditional jumps
                    } else {
                        feature_vector[7] += 1. // No. of generic instructions (mov, lea)
                    }
                } else if architecture == "MIPS" {
                    // This is defaulted to zero as we have no "stack" operations in MIPS
                    feature_vector[0] += 0.; // No. of Stack Operations
                    if MIPS_ARITHMETIC.contains(&opcode) {
                        feature_vector[1] += 1. // No. of Arithmetic Instructions
                    } else if MIPS_LOGIC.contains(&opcode) {
                        feature_vector[2] += 1. // No. of Logical Instructions
                    } else if MIPS_COMPARE.contains(&opcode) {
                        feature_vector[3] += 1. // No. of comparative instructions
                    } else if MIPS_CALL.contains(&opcode)
                        && ins.disasm.as_ref().unwrap().contains("imp")
                    {
                        feature_vector[4] += 1. // No. of library function calls
                    } else if MIPS_UNCOND.contains(&opcode) {
                        feature_vector[5] += 1. // No. of unconditional jumps
                    } else if MIPS_COND.contains(&opcode) {
                        feature_vector[6] += 1. // No. of conditional jumps
                    } else {
                        feature_vector[7] += 1. // No. of generic instructions (mov, lea)
                    }
                } else {
                    unreachable!(
                        "Invalid Architecture - This shouldn't happen! Got {}",
                        architecture
                    )
                }
            }
        }
        feature_vector
    }

    // Gets the number of offspring for a basic block
    // Note: The swithop counting below is naive, it does not
    // check to see if the fail/jump targets are also switch case targets.
    // This could result in incorrect counts
    // TODO: Fix this.
    fn get_no_offspring(&self) -> f64 {
        let mut num_offspring: f64 = 0.;

        if self.fail != 0 {
            num_offspring += 1.
        }

        if self.jump != 0 {
            num_offspring += 1.
        }

        if self.switchop.is_some() {
            num_offspring += self.switchop.as_ref().unwrap().cases.len() as f64
        }
        num_offspring
    }

    // Get the edges associated with a given basic block.
    // This function only considers valid edges as being
    // fail, jumps or switchops that reside within the function itself.
    // If there are edges that jump to another function outside of the program
    // these edges are ignored.
    //
    // This function updates the provide mutable edge list with a three-tuple which
    // represents (src, dst, weight). The weight in this case is the type of edge where
    // 1 denotes jump, 2 denotes fail, 3 denotes switchop
    pub fn get_block_edges(
        &self,
        addr_idxs: &mut Vec<i64>,
        edge_list: &mut Vec<(u32, u32, u32)>,
        max_offset: u64,
        min_offset: u64,
    ) {
        let mut addr: i64 = self.offset;
        let mut jump: i64 = self.jump;
        let mut fail: i64 = self.fail;

        if addr < min_offset.try_into().unwrap() || addr >= max_offset.try_into().unwrap() {
            addr = -1;
        }

        if jump < min_offset.try_into().unwrap() || jump >= max_offset.try_into().unwrap() {
            jump = -1;
        }

        if fail < min_offset.try_into().unwrap() || fail >= max_offset.try_into().unwrap() {
            fail = -1;
        }

        if addr != -1 && !addr_idxs.contains(&addr) {
            addr_idxs.push(addr);
        }
        if jump != -1 && !addr_idxs.contains(&jump) {
            addr_idxs.push(jump)
        }

        if fail != -1 && !addr_idxs.contains(&fail) {
            addr_idxs.push(fail)
        }

        let addr_idx = addr_idxs.iter().position(|&p| p == addr);

        if let Some(addr_idx) = addr_idx {
            if jump != -1 {
                let jump_idx = addr_idxs.iter().position(|&p| p == jump).unwrap();
                edge_list.push((addr_idx as u32, jump_idx as u32, 1));
            }

            if fail != -1 {
                let fail_idx = addr_idxs.iter().position(|&p| p == fail).unwrap();
                edge_list.push((addr_idx as u32, fail_idx as u32, 2));
            }

            if self.switchop.is_some() {
                for item in &self.switchop.as_ref().unwrap().cases {
                    if !addr_idxs.contains(&item.jump) {
                        addr_idxs.push(item.jump)
                    }
                    let item_addr_idx = addr_idxs.iter().position(|&p| p == item.jump).unwrap();
                    edge_list.push((addr_idx as u32, item_addr_idx as u32, 3));
                }
            }
        }
    }

    // Creates a vector containing the ESIL representation for
    // each instruction within a given basic block
    pub fn get_esil_bb(&self, reg_norm: bool) -> Vec<String> {
        let mut esil_ins: Vec<String> = Vec::new();
        for op in &self.ops {
            if op.esil.is_some() && op.esil.as_ref().unwrap().len() > 1 {
                let esil_single = &op.esil.as_ref().unwrap();
                debug!("ESIL Single (prior to norm): {:?}", esil_single);
                let normd = normalise_esil_simple(esil_single, &op.r#type, reg_norm);
                esil_ins.push((*normd).to_string())
            }
        }

        esil_ins
    }

    pub fn get_disasm_bb(&self, reg_norm: bool) -> Vec<String> {
        let mut disasm_ins: Vec<String> = Vec::new();
        for op in &self.ops {
            if op.disasm.is_some() && op.disasm.as_ref().unwrap().len() > 1 {
                let disasm_single = &op.disasm.as_ref().unwrap();
                let normd = normalise_disasm_simple(disasm_single, reg_norm);
                disasm_ins.push((*normd).to_string());
            }
        }
        disasm_ins
    }

    pub fn get_ins(&self, reg_norm: bool) -> Vec<String> {
        let mut disasm_ins: Vec<String> = Vec::new();
        for op in &self.ops {
            if op.disasm.is_some() {
                let disasm_single = &op.disasm.as_ref().unwrap();
                let normd = normalise_disasm_simple(disasm_single, reg_norm);
                disasm_ins.push((*normd).to_string())
            }
        }
        disasm_ins
    }

    pub fn get_n_ins(&self, with_swithops: bool) -> u16 {
        let mut n_ins: u16 = 0;
        if self.switchop.is_some() && with_swithops {
            n_ins += self.switchop.as_ref().unwrap().cases.len() as u16
        }
        n_ins += self.ops.len() as u16;

        n_ins
    }

    pub fn get_tiknib_features_bb(&self, architecture: &String) -> TikNibFeaturesBB {
        let mut features = TikNibFeaturesBB {
            arithshift: 0.0,
            compare: 0.0,
            ctransfer: 0.0,
            ctransfercond: 0.0,
            dtransfer: 0.0,
            float: 0.0,
            total: 0.0,
        };

        for ins in self.ops.iter() {
            if ins.r#type != "invalid" {
                let opcode = ins
                    .opcode
                    .as_ref()
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap();
                if architecture == "ARM" {
                    // Arith + Shifts
                    if ARM_GRP_ARITH.contains(&opcode) || ARM_GRP_SHIFT.contains(&opcode) {
                        features.arithshift += 1.0
                    }
                    // Compare
                    if ARM_GRP_CMP.contains(&opcode) || ARM_GRP_FLOAT_CMP.contains(&opcode) {
                        features.compare += 1.0
                    }
                    // Call Transfer
                    if ARM_GRP_CTRANSFER.contains(&opcode) {
                        features.ctransfer += 1.0
                    }
                    // Call Transfer + Cond
                    if ARM_GRP_CTRANSFER.contains(&opcode)
                        || ARM_GRP_COND_CTRANSFER.contains(&opcode)
                    {
                        features.ctransfercond += 1.0
                    }
                    // Data Transfer
                    if ARM_GRP_DTRANSFER.contains(&opcode)
                        || ARM_GRP_FLOAT_DTRANSFER.contains(&opcode)
                    {
                        features.dtransfer += 1.0
                    }

                    // FLoat Operations
                    if ARM_GRP_FLOAT_DTRANSFER.contains(&opcode)
                        || ARM_GRP_FLOAT_CMP.contains(&opcode)
                        || ARM_GRP_FLOAT_ARITH.contains(&opcode)
                    {
                        features.float += 1.0
                    }
                    // total
                    features.total += 1.0
                } else if architecture == "MIPS" {
                    // Arith + Shifts
                    if MIPS_GRP_ARITH.contains(&opcode) || MIPS_GRP_SHIFT.contains(&opcode) {
                        features.arithshift += 1.0
                    }
                    // Compare
                    if MIPS_GRP_CMP.contains(&opcode) || MIPS_GRP_FLOAT_CMP.contains(&opcode) {
                        features.compare += 1.0
                    }
                    // Call Transfer
                    if MIPS_GRP_CTRANSFER.contains(&opcode) {
                        features.ctransfer += 1.0
                    }
                    // Call Transfer + Cond
                    if MIPS_GRP_CTRANSFER.contains(&opcode)
                        || MIPS_GRP_COND_CTRANSFER.contains(&opcode)
                    {
                        features.ctransfercond += 1.0
                    }
                    // Data Transfer
                    if MIPS_GRP_DTRANSFER.contains(&opcode)
                        || MIPS_GRP_FLOAT_DTRANSFER.contains(&opcode)
                    {
                        features.dtransfer += 1.0
                    }

                    // FLoat Operations
                    if MIPS_GRP_FLOAT_DTRANSFER.contains(&opcode)
                        || MIPS_GRP_FLOAT_CMP.contains(&opcode)
                        || MIPS_GRP_FLOAT_ARITH.contains(&opcode)
                    {
                        features.float += 1.0
                    }
                    // total
                    features.total += 1.0
                } else if architecture == "X86" {
                    // Arith + Shifts
                    if X86_GRP_ARITH.contains(&opcode) || X86_GRP_SHIFT.contains(&opcode) {
                        features.arithshift += 1.0
                    }
                    // Compare
                    if X86_GRP_CMP.contains(&opcode) || X86_GRP_FLOAT_CMP.contains(&opcode) {
                        features.compare += 1.0
                    }
                    // Call Transfer
                    if X86_GRP_CTRANSFER.contains(&opcode) {
                        features.ctransfer += 1.0
                    }
                    // Call Transfer + Cond
                    if X86_GRP_CTRANSFER.contains(&opcode)
                        || X86_GRP_COND_CTRANSFER.contains(&opcode)
                    {
                        features.ctransfercond += 1.0
                    }
                    // Data Transfer
                    if X86_GRP_DTRANSFER.contains(&opcode)
                        || X86_GRP_FLOAT_DTRANSFER.contains(&opcode)
                    {
                        features.dtransfer += 1.0
                    }

                    // FLoat Operations
                    if X86_GRP_FLOAT_DTRANSFER.contains(&opcode)
                        || X86_GRP_FLOAT_CMP.contains(&opcode)
                        || X86_GRP_FLOAT_ARITH.contains(&opcode)
                    {
                        features.float += 1.0
                    }
                    // total
                    features.total += 1.0
                } else {
                    unreachable!("The architecture provided is not possible.")
                }
            }
        }
        features
    }
    pub fn get_tiknib_features_vec(&self, architecture: &String) -> Vec<f64> {
        Self::get_tiknib_features_bb(self, architecture).to_vec()
    }
}

mod tests {

    // Lol - something for anyone reviewing this \o/
    #[test]
    fn test_example_in_bb_rs() {
        assert_eq!(1, 1);
    }
}
