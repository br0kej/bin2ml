use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_json::Value;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AFIJFunctionInfo {
    pub offset: i64,
    pub name: String,
    pub size: i64,
    #[serde(rename = "is-pure")]
    pub is_pure: String,
    pub realsz: i64,
    pub noreturn: bool,
    pub stackframe: i64,
    pub calltype: String,
    pub cost: i64,
    pub cc: i64,
    pub bits: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub nbbs: i64,
    #[serde(rename = "is-lineal")]
    pub is_lineal: bool,
    pub ninstrs: i64,
    pub edges: i64,
    pub ebbs: i64,
    pub signature: String,
    pub minbound: i64,
    pub maxbound: i64,
    pub callrefs: Option<Vec<Callref>>,
    // TODO: Need to fix this and change to string instead of i64 to get round large random numbers
    pub datarefs: Option<Vec<Dataref>>,
    pub codexrefs: Option<Vec<Codexref>>,
    pub dataxrefs: Option<Vec<i64>>,
    pub indegree: Option<i64>,
    pub outdegree: Option<i64>,
    pub nlocals: Option<i64>,
    pub nargs: Option<i64>,
    pub bpvars: Option<Vec<Bpvar>>,
    // Cannot find a good example of an spvars yet
    pub spvars: Option<Vec<Value>>,
    pub regvars: Option<Vec<Regvar>>,
    pub difftype: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callref {
    #[serde(deserialize_with = "deserialize_string_from_number")]
    pub addr: String,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", transparent)]
pub struct Dataref {
    #[serde(deserialize_with = "deserialize_string_from_number")]
    value: String,
}
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Codexref {
    pub addr: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bpvar {
    pub name: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "ref")]
    pub ref_field: Ref,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ref {
    pub base: String,
    pub offset: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Regvar {
    pub name: String,
    pub kind: String,
    #[serde(rename = "type")]
    pub type_field: String,
    #[serde(rename = "ref")]
    pub ref_field: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AFIJFeatureSubset {
    pub name: String,
    pub ninstrs: i64,
    pub edges: i64,
    pub indegree: i64,
    pub outdegree: i64,
    pub nlocals: i64,
    pub nargs: i64,
    pub signature: String,
}

impl From<&AFIJFunctionInfo> for AFIJFeatureSubset {
    fn from(src: &AFIJFunctionInfo) -> AFIJFeatureSubset {
        AFIJFeatureSubset {
            name: src.name.clone(),
            ninstrs: src.ninstrs,
            edges: src.edges,
            indegree: src.indegree.unwrap_or(0),
            outdegree: src.outdegree.unwrap_or(0),
            nlocals: src.nlocals.unwrap_or(0),
            nargs: src.nargs.unwrap_or(0),
            signature: src.signature.clone(),
        }
    }
}
