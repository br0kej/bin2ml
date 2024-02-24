use crate::afij::AFIJFeatureSubset;
use crate::agfj::TikNibFuncFeatures;
use crate::files::FunctionMetadataTypes;
use ordered_float::OrderedFloat;
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

impl From<(AFIJFeatureSubset, TikNibFuncFeatures)> for FinfoTiknib {
    fn from(value: (AFIJFeatureSubset, TikNibFuncFeatures)) -> Self {
        FinfoTiknib {
            name: value.0.name,
            edges: value.0.edges,
            indegree: value.0.indegree,
            outdegree: value.0.outdegree,
            nlocals: value.0.nlocals,
            nargs: value.0.nargs,
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
