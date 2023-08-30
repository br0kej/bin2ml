use serde::{Deserialize, Serialize};
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
    pub datarefs: Option<Vec<i64>>,
    pub codexrefs: Option<Vec<Codexref>>,
    pub dataxrefs: Option<Vec<i64>>,
    pub indegree: i64,
    pub outdegree: i64,
    pub nlocals: i64,
    pub nargs: i64,
    pub bpvars: Vec<Bpvar>,
    // Cannot find a good example of an spvars yet
    pub spvars: Vec<Value>,
    pub regvars: Vec<Regvar>,
    pub difftype: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Callref {
    pub addr: i64,
    #[serde(rename = "type")]
    pub type_field: String,
    pub at: i64,
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