// Added to enable format expect's which print
// the error and some extra info
#![allow(clippy::expect_fun_call)]

use clap::{Parser, Subcommand};
use std::fmt;
#[macro_use]
extern crate log;
use clap::builder::TypedValueParser;
use env_logger::Env;
use indicatif::{ParallelProgressIterator, ProgressIterator};

use mimalloc::MiMalloc;
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelRefIterator;
use std::path::{Path, PathBuf};
use std::process::exit;
use walkdir::WalkDir;

pub mod afij;
pub mod agcj;
pub mod agfj;
pub mod bb;
#[cfg(feature = "goblin")]
pub mod binnfo;
mod combos;
pub mod consts;
pub mod dedup;
pub mod errors;
pub mod extract;
pub mod files;
#[cfg(feature = "inference")]
pub mod inference;
pub mod networkx;
pub mod normalisation;
mod pcode;
pub mod processors;
pub mod tokeniser;
pub mod utils;
mod validate;

use crate::dedup::{CGCorpus, EsilFuncStringCorpus};
use crate::extract::ExtractionJobType;
use crate::files::{AFIJFile, AGCJFile, FunctionMetadataTypes, TikNibFuncMetaFile};
use crate::tokeniser::{train_byte_bpe_tokeniser, TokeniserType};
use crate::utils::get_save_file_path;

use crate::combos::{ComboJob, FinfoTiknibFile};
use crate::networkx::CallGraphNodeFeatureType;
use crate::pcode::{PCodeFile, PCodeFileTypes};
use crate::validate::validate_input;
use bb::{FeatureType, InstructionMode};
#[cfg(feature = "goblin")]
use binnfo::goblin_info;
use extract::{ExtractionJob, PathType};
use files::{AGFJFile, FormatMode};
#[cfg(feature = "inference")]
use inference::inference;
#[cfg(feature = "inference")]
use processors::agfj_graph_embedded_feats;
use processors::agfj_graph_statistical_features;
use utils::get_json_paths_from_dir;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(PartialEq, Copy, Clone)]
pub enum DataType {
    Cfg,
    Cg,
    OneHopCg,
    CgWithCallers,
    OneHopCgWithcallers,
    GlobalCg,
    Invalid,
}

impl fmt::Display for DataType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DataType::Cfg => write!(f, "Control Flow Graph"),
            DataType::Cg => write!(f, "Call Graph"),
            DataType::CgWithCallers => write!(f, "Call Graph with Callers"),
            DataType::OneHopCg => write!(f, "One Hop Call Graph"),
            DataType::OneHopCgWithcallers => write!(f, "One Hop Call Graph with Callers"),
            DataType::GlobalCg => write!(f, "Globlal Call Graph"),
            DataType::Invalid => write!(f, "Invalid"),
        }
    }
}

/// Turn binaries into machine learning ready formats
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}
#[derive(Subcommand, Clone)]
enum GenerateSubCommands {
    /// Generate graphs from extracted data
    Graphs {
        /// The path to a JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "FILENAME")]
        path: PathBuf,

        /// The target data type
        #[arg(short, long, value_name = "DATA_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["cfg", "cg", "onehopcg", "cgcallers", "onehopcgcallers", "globalcg"])
        .map(|s| s.parse::<String>().unwrap()),)]
        data_type: String,

        /// The output path for the processed Networkx graphs (1 per function)
        #[arg(short, long, value_name = "OUTPUT")]
        output_path: PathBuf,

        /// The type of features to generate per basic block (node)
        #[arg(short, long, value_name = "FEATURE_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["gemini", "discovre", "dgis", "tiknib", "disasm", "esil", "pcode", "pseudo"])
        .map(|s| s.parse::<String>().unwrap()),)]
        feature_type: Option<String>,

        /// The min number of basic blocks. Any CFG's below this number will be skipped
        #[arg(long, default_value = "5")]
        min_blocks: Option<u16>,

        /// The filepath to a HuggingFace tokeniser.json
        #[cfg(feature = "inference")]
        #[arg(short, long, value_name = "TOKENISER_FP")]
        tokeniser_fp: Option<String>,

        /// The filepath to a TorchScript HuggingFace Model
        #[cfg(feature = "inference")]
        #[arg(long, value_name = "MODEL_FP")]
        model_fp: Option<String>,

        /// Flag to mean_pool embedding output
        #[cfg(feature = "inference")]
        #[arg(long, default_value = "true")]
        mean_pool: bool,

        /// Embedding dimension
        #[cfg(feature = "inference")]
        #[arg(short, long, value_name = "EMBED_DIM")]
        embed_dim: Option<i64>,

        /// Num Threads
        #[arg(short, long)]
        num_threads: usize,

        /// Toggle for call graphs to include AFIJ feature subsets (For call graphs)
        #[arg(long, default_value = "false")]
        with_features: bool,

        /// Filepath to the AFIJ function metadata (For call graphs)
        #[arg(long)]
        metadata_path: Option<PathBuf>,

        /// Include unknown functions (For call graphs)
        #[arg(long, default_value = "false")]
        include_unk: bool,

        /// Metadata Type (For call graphs)
        #[arg(short, long, value_name = "METADATA_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["finfo", "tiknib", "finfo-tiknib"])
        .map(|s| s.parse::<String>().unwrap()),)]
        metadata_type: Option<String>,
    },
    /// Generate NLP data from extracted data
    Nlp {
        /// The path to a JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "FILENAME")]
        path: PathBuf,

        /// The type of data to be generated
        #[arg(short, long, value_name = "DATA_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["esil", "disasm", "pcode"])
        .map(|s| s.parse::<String>().unwrap()),)]
        instruction_type: String,

        /// The min number of basic blocks. Any CFG's below this number will be skipped
        #[arg(long, default_value = "5")]
        min_blocks: u16,

        /// The output path for the processed data
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        data_out_path: PathBuf,

        /// The format of the output data
        #[arg(short, long, value_name = "FORMAT", value_parser = clap::builder::PossibleValuesParser::new(["single", "funcstring"])
        .map(|s| s.parse::<String>().unwrap()))]
        output_format: String,

        /// Toggle to determine if blocks are sampled in a random walk nature
        #[arg(long, default_value = "false")]
        random_walk: bool,

        /// Toggle register normalisation
        #[arg(long, default_value = "false")]
        reg_norm: bool,

        /// Toggle to determine if pairs should be generated
        #[arg(long, default_value = "false")]
        pairs: bool,

        /// Determine the pcode filetype
        #[arg(long, value_parser = clap::builder::PossibleValuesParser::new(["pcode-func", "pcode-bb"])
        .map(|s| s.parse::<String>().unwrap()))]
        pcode_file_format: Option<String>,
    },
    /// Generate metadata/feature subsets from extracted data
    Metadata {
        /// The path to an afji JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "INPUT_PATH")]
        input_path: PathBuf,
        /// The path for the generated output
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: PathBuf,
        /// Data Source Type
        #[arg(short, long, value_parser = clap::builder::PossibleValuesParser::new(["finfo", "tiknib"])
            .map(|s| s.parse::<String>().unwrap()))]
        data_source_type: String,
        /// Toggle for extended version of finfo
        #[arg(short, long)]
        extended: bool,
    },
    /// Generate tokenisers from extracted data
    Tokeniser {
        #[arg(short, long, value_name = "DATA")]
        data: String,
        /// The path to the text file containing the corpus to process
        #[arg(
            short,
            long,
            value_name = "OUTPUT_NAME",
            default_value = "tokeniser.json"
        )]
        output_name: String,
        /// The path to the text file containing the corpus to process
        #[arg(short, long, value_name = "VOCAB_SIZE", default_value = "10000")]
        vocab_size: usize,
        /// The type of tokeniser to create
        #[arg(short, long, value_name = "BPE or Byte-BPE", default_value = "BPE")]
        tokeniser_type: String,
    },
    /// Generate combinations of extracted data - Primaryily metadata objects
    Combos {
        #[arg(short, long, value_name = "INPUT_PATH")]
        input_path: PathBuf,
        /// The path for the generated output
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: PathBuf,
        /// Combo Type
        #[arg(short, long, value_parser = clap::builder::PossibleValuesParser::new(["finfo+tiknib", "finfoe+tiknib"])
        .map(|s| s.parse::<String>().unwrap()))]
        combo_type: String,
        /// Number of threads
        #[arg(short, long, default_value = "2")]
        num_threads: usize,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Get summary information for a binary
    #[cfg(feature = "goblin")]
    Info {
        /// The path to the target binary
        #[arg(short, long, value_name = "FILENAME")]
        path: Option<PathBuf>,
    },
    /// Generate processed data from extracted raw data
    Generate {
        #[command(subcommand)]
        subcommands: GenerateSubCommands,
    },
    /// Extract raw data from input binaries
    /// Extract raw data from input binaries
    Extract {
        /// The path to the dir or binary to be processed
        #[arg(short, long, value_name = "DIR")]
        fpath: PathBuf,

        /// The path for the output directory
        #[arg(short, long, value_name = "OUTPUT_DIR")]
        output_dir: PathBuf,

        /// The extraction modes (multiple can be specified)
        #[arg(short, long, value_name = "EXTRACT_MODE",
        value_parser = clap::builder::PossibleValuesParser::new([
        "finfo", "reg", "cfg", "func-xrefs", "cg", "decomp",
        "pcode-func", "pcode-bb", "localvar-xrefs", "strings", "bytes"
        ])
        .map(|s| s.parse::<String>().unwrap()),
        num_args = 1..,
        required = true)]
        modes: Vec<String>,

        /// The number of threads Rayon can use when parallel processing
        #[arg(short, long, value_name = "NUM_THREADS", default_value = "2")]
        num_threads: usize,

        #[arg(long, default_value = "false")]
        debug: bool,

        #[arg(long, default_value = "false")]
        extended_analysis: bool,

        #[arg(long, default_value = "true")]
        use_curl_pdb: bool,

        #[arg(long, default_value = "false")]
        with_annotations: bool,
    },
    /// Generate single embeddings on the fly
    ///
    /// This part of the CLI has several assumptions around the model used. The inference
    /// functions assume two things:
    ///
    /// 1. That the HuggingFace Model has been amended to output only one Tensor, not an output dictionary
    /// 2. That the input sequences are all going to be attended too i.e there are no SOS or EOS tokens.
    #[cfg(feature = "inference")]
    Inference {
        /// The sequence to embed
        #[arg(short, long, value_name = "SEQ_TO_EMBED")]
        sequence: String,
        /// The filepath to a HuggingFace tokeniser.json
        #[arg(short, long, value_name = "TOKENISER_FP")]
        tokeniser_fp: String,
        /// The filepath to a TorchScript HuggingFace Model
        #[arg(short, long, value_name = "MODEL_FP")]
        model_fp: String,
        /// Flag to mean_pool embedding output
        #[arg(long)]
        mean_pool: bool,
    },
    /// Utility to remove duplicate entries within processed data
    Dedup {
        #[command(subcommand)]
        subcommands: DedupSubCommands,
    },
}

#[derive(Subcommand, Clone)]
enum DedupSubCommands {
    /// De-Dup generated call graphs
    Cgs {
        /// The filename to dedup
        #[arg(short, long, value_name = "FILENAME")]
        filename: PathBuf,

        /// Output path to save dedup corpus
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: PathBuf,

        /// Number of threads to use with Rayon
        #[arg(short, long, value_name = "NUM_THREADS", default_value = "2")]
        num_threads: usize,

        /// The filepath_format of the dataset
        #[arg(long,value_parser = clap::builder::PossibleValuesParser::new(["cisco", "binkit", "trex", "binarycorp"])
        .map(|s| s.parse::<String>().unwrap()), required = true)]
        filepath_format: String,

        /// The node feature type for call graphs
        #[arg(long,value_parser = clap::builder::PossibleValuesParser::new(["cgmeta", "cgname", "tiknib"])
        .map(|s| s.parse::<String>().unwrap()), required = true)]
        node_feature_type: String,

        /// Toggle to remove inplace (i.e delete duplicates)
        #[arg(long)]
        inplace: bool,
    },
    /// De-dup generate ESIL strings
    Esil {
        /// The filename to dedup
        #[arg(short, long, value_name = "FILENAME")]
        filename: PathBuf,

        /// Output path to save dedup corpus
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: PathBuf,

        /// Toggle to print statistics of number of functions before and after dedup
        #[arg(long, default_value = "false")]
        print_stats: bool,

        /// Toggle for just calculating stats without creating any files
        #[arg(long, default_value = "false")]
        just_stats: bool,

        /// Number of threads to use with Rayon
        #[arg(short, long, value_name = "NUM_THREADS", default_value = "2")]
        num_threads: usize,

        /// Toggle whether to dedup based on hashing only the value (and ignoring the key)
        #[arg(short, long, default_value = "false")]
        just_hash_value: bool,
    },
}

fn main() {
    let env = Env::default()
        .filter_or("LOG_LEVEL", "warn")
        .write_style_or("LOG_STYLE", "always");

    env_logger::init_from_env(env);
    let cli = Cli::parse();
    match &cli.command {
        #[cfg(feature = "goblin")]
        Commands::Info { path } => {
            info!("starting Information Gathering");
            if let Some(fpath) = &path {
                goblin_info(fpath).expect("Failed to get info!");
            }
        }
        Commands::Generate { subcommands } => match subcommands {
            GenerateSubCommands::Graphs {
                path,
                data_type: graph_type,
                min_blocks,
                output_path,
                feature_type,
                #[cfg(feature = "inference")]
                tokeniser_fp,
                #[cfg(feature = "inference")]
                model_fp,
                #[cfg(feature = "inference")]
                mean_pool,
                #[cfg(feature = "inference")]
                embed_dim,
                with_features,
                metadata_path,
                include_unk,
                num_threads,
                metadata_type,
            } => {
                let graph_data_type = match graph_type.as_str() {
                    "cfg" => DataType::Cfg,
                    "cg" => DataType::Cg,
                    "onehopcg" => DataType::OneHopCg,
                    "cgcallers" => DataType::CgWithCallers,
                    "onehopcgcallers" => DataType::OneHopCgWithcallers,
                    "globalcg" => DataType::GlobalCg,
                    _ => DataType::Invalid,
                };

                rayon::ThreadPoolBuilder::new()
                    .num_threads(*num_threads)
                    .build_global()
                    .unwrap();

                if graph_data_type == DataType::Cfg && *with_features {
                    warn!("The 'with_features' toggle is set but is not support for CFG generation. Will ignore.")
                };

                if !path.exists() {
                    error!("{:?} does not exist!", path);
                    exit(1)
                }
                info!("Chosen Graph Type: {}", graph_data_type);
                if graph_data_type == DataType::Cfg {
                    if feature_type.is_some() {
                        let feature_vec_type = match feature_type.as_ref().unwrap().as_str() {
                            "gemini" => FeatureType::Gemini,
                            "discovre" => FeatureType::DiscovRE,
                            "dgis" => FeatureType::DGIS,
                            "encode" => FeatureType::Encoded,
                            "tiknib" => FeatureType::Tiknib,
                            "disasm" => FeatureType::Disasm,
                            "esil" => FeatureType::Esil,
                            #[cfg(feature = "inference")]
                            "embed" => FeatureType::ModelEmbedded,
                            "pcode" => FeatureType::Pcode,
                            "pseudo" => FeatureType::Pseudo,
                            _ => FeatureType::Invalid,
                        };

                        if feature_vec_type == FeatureType::Invalid {
                            warn!("Invalid feature type: {}", feature_type.as_ref().unwrap());
                            exit(1)
                        } else if feature_vec_type == FeatureType::Gemini
                            || feature_vec_type == FeatureType::DiscovRE
                            || feature_vec_type == FeatureType::DGIS
                            || feature_vec_type == FeatureType::Tiknib
                            || feature_vec_type == FeatureType::Disasm
                            || feature_vec_type == FeatureType::Esil
                            || feature_vec_type == FeatureType::Pseudo
                        {
                            info!(
                                "Creating graphs with {:?} feature vectors.",
                                feature_vec_type
                            );

                            if Path::new(path).is_file() {
                                validate_input(path, "cfg");
                                info!("Single file found");
                                agfj_graph_statistical_features(
                                    path,
                                    &min_blocks.unwrap(),
                                    output_path,
                                    feature_vec_type,
                                )
                            } else {
                                info!("Multiple files found. Will parallel process.");
                                for file in
                                    WalkDir::new(path).into_iter().filter_map(|file| file.ok())
                                {
                                    if file.path().to_string_lossy().ends_with(".json") {
                                        validate_input(file.path(), "cfg");
                                        agfj_graph_statistical_features(
                                            file.path(),
                                            &min_blocks.unwrap(),
                                            output_path,
                                            feature_vec_type,
                                        )
                                    }
                                }
                            }
                        } else if feature_vec_type == FeatureType::Encoded {
                            todo!("Need to implement Encoded FeatureTypes!")
                        } else if cfg!(inference) {
                            #[cfg(feature = "inference")]
                            if feature_vec_type == FeatureType::ModelEmbedded {
                                if tokeniser_fp.is_none() || model_fp.is_none() {
                                    println!("Both Tokenizer and Model file paths are needed");
                                    exit(100)
                                } else {
                                    agfj_graph_embedded_feats(
                                        path,
                                        &min_blocks.unwrap(),
                                        output_path,
                                        feature_vec_type,
                                        tokeniser_fp,
                                        model_fp,
                                        mean_pool,
                                        embed_dim,
                                    );
                                }
                            }
                        } else if feature_vec_type == FeatureType::Pcode {
                            if Path::new(path).is_file() {
                                validate_input(path, "cfg");
                                info!("Single file found");
                                let mut file = PCodeFile {
                                    filename: path.to_owned(),
                                    pcode_obj: None,
                                    output_path: output_path.to_owned(),
                                    min_blocks: *min_blocks,
                                    instruction_pairs: false,
                                    format_type: FormatMode::SingleInstruction,
                                    pcode_file_type: PCodeFileTypes::PCodeJsonFile,
                                };
                                let file_ret = file.load_and_deserialize().is_ok();
                                if file_ret {
                                    let cfg_gen_ret =
                                        file.pcode_json_with_bb_info_generate_cfg().is_ok();
                                    if cfg_gen_ret {
                                        info!("Successfully generated CFG's with PCode features")
                                    } else {
                                        error!("Failed to generate CFG's with PCode features")
                                    }
                                }
                            } else {
                                info!("[L551] Multiple files found. Will parallel process.");
                                for file in
                                    WalkDir::new(path).into_iter().filter_map(|file| file.ok())
                                {
                                    if file.path().to_string_lossy().ends_with(".json") {
                                        validate_input(file.path(), "cfg");
                                        let mut file = PCodeFile {
                                            filename: file.path().to_owned(),
                                            pcode_obj: None,
                                            output_path: output_path.to_owned(),
                                            min_blocks: *min_blocks,
                                            instruction_pairs: false,
                                            format_type: FormatMode::SingleInstruction,
                                            pcode_file_type: PCodeFileTypes::PCodeJsonFile,
                                        };
                                        let file_ret = file.load_and_deserialize().is_ok();
                                        if file_ret {
                                            let cfg_gen_ret =
                                                file.pcode_json_with_bb_info_generate_cfg().is_ok();
                                            if cfg_gen_ret {
                                                info!("Successfully generated CFG's with PCode features")
                                            } else {
                                                error!(
                                                    "Failed to generate CFG's with PCode features"
                                                )
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else {
                        error!("--feature-type/-f is required for creating CFG's")
                    }
                } else if Path::new(path).is_file() {
                    validate_input(path, "cg");
                    let mut file = match with_features {
                        true => {
                            let mut metadata = AFIJFile {
                                filename: metadata_path.as_ref().unwrap().to_path_buf(),
                                function_info: None,
                                output_path: PathBuf::new(),
                            };
                            debug!("AFIJ Object: {:?}", metadata);
                            metadata
                                .load_and_deserialize()
                                .expect("Unable to load file");
                            let metadata_subset = metadata.subset(false);
                            AGCJFile {
                                filename: path.clone(),
                                function_call_graphs: None,
                                output_path: output_path.clone(),
                                function_metadata: Some(metadata_subset),
                                include_unk: *include_unk,
                            }
                        }
                        false => AGCJFile {
                            filename: path.clone(),
                            function_call_graphs: None,
                            output_path: output_path.clone(),
                            function_metadata: None,
                            include_unk: *include_unk,
                        },
                    };

                    file.load_and_deserialize()
                        .expect("Unable to load and deserialize JSON");
                    file.process_based_on_graph_data_type(
                        graph_data_type,
                        with_features,
                        metadata_type.clone(),
                    );
                } else {
                    debug!("Multiple files found");

                    if metadata_path.is_none() & with_features {
                        error!("with features active - require --metadata-path argument");
                        exit(1)
                    };

                    let mut file_paths_vec = get_json_paths_from_dir(path, Some("_cg".to_string()));
                    info!(
                        "{} files found. Beginning Processing.",
                        file_paths_vec.len()
                    );
                    // if without metadata
                    if !with_features & metadata_type.is_none() {
                        debug!("Creating call graphs without any node features");
                        file_paths_vec.par_iter().progress().for_each(|path| {
                            let suffix = graph_type.to_owned().to_string();
                            let full_output_path = get_save_file_path(
                                &PathBuf::from(path),
                                output_path,
                                Some(".json".to_string()),
                                Some(suffix),
                                None,
                            );
                            if !full_output_path.is_dir() {
                                let mut file = AGCJFile {
                                    filename: path.to_owned().parse().unwrap(),
                                    function_call_graphs: None,
                                    output_path: output_path.to_owned(),
                                    function_metadata: None,
                                    include_unk: *include_unk,
                                };
                                debug!("Processing {:?}", file.filename);
                                file.load_and_deserialize()
                                    .expect("Unable to load and deserialize JSON");
                                file.process_based_on_graph_data_type(
                                    graph_data_type,
                                    with_features,
                                    metadata_type.clone(),
                                );
                            } else {
                                info!(
                                    "Skipping {} as already exists",
                                    full_output_path.to_string_lossy()
                                )
                            }
                        })
                    } else {
                        info!("Creating call graphs with node features");
                        debug!("Getting metadata file paths");
                        // its more than one file
                        if metadata_path.is_none() {
                            error!("with features active - require --metadata-path argument");
                            exit(1)
                        };

                        if with_features & metadata_type.is_none() {
                            error!("with features requires metadata_type to be set");
                            exit(1)
                        };

                        let mut metadata_paths_vec = get_json_paths_from_dir(
                            metadata_path.as_ref().unwrap(),
                            Some(metadata_type.as_ref().unwrap().to_string()),
                        );

                        file_paths_vec.sort();
                        metadata_paths_vec.sort();

                        assert_eq!(file_paths_vec.len(), metadata_paths_vec.len());
                        let combined_cgs_metadata = file_paths_vec
                            .into_iter()
                            .zip(metadata_paths_vec)
                            .collect::<Vec<_>>();

                        combined_cgs_metadata.par_iter().progress().for_each(
                            |(filepath, metapath)| {
                                let suffix = format!("{}-meta", graph_type.to_owned());
                                let full_output_path = get_save_file_path(
                                    &PathBuf::from(filepath),
                                    output_path,
                                    Some(".json".to_string()),
                                    Some(suffix),
                                    None,
                                );
                                if !full_output_path.is_dir() {
                                    let mut file = {
                                        let metadata: Option<FunctionMetadataTypes>;
                                        if metadata_type.clone().unwrap() == *"finfo" {
                                            let mut metadata_file = AFIJFile {
                                                filename: PathBuf::from(metapath),
                                                function_info: None,
                                                output_path: PathBuf::new(),
                                            };
                                            debug!(
                                                "Attempting to load metadata file: {}",
                                                metapath
                                            );
                                            metadata_file
                                                .load_and_deserialize()
                                                .expect("Unable to load associated metadata file");
                                            metadata = Some(metadata_file.subset(false));
                                        } else if metadata_type.clone().unwrap() == *"tiknib" {
                                            let mut metadata_file = TikNibFuncMetaFile {
                                                filename: PathBuf::from(metapath),
                                                function_info: None,
                                                output_path: PathBuf::new(),
                                            };

                                            metadata_file
                                                .load_and_deserialize()
                                                .expect("Unable to load associated metadata file");
                                            metadata = Some(metadata_file.subset());
                                        } else if metadata_type.clone().unwrap() == *"finfo-tiknib"
                                        {
                                            let mut metadata_file = FinfoTiknibFile {
                                                filename: PathBuf::from(metapath),
                                                function_info: None,
                                                output_path: PathBuf::new(),
                                            };
                                            debug!(
                                                "Attempting to load metadata file: {}",
                                                metapath
                                            );
                                            metadata_file
                                                .load_and_deserialize()
                                                .expect("Unable to load associated metadata file");
                                            metadata =
                                                Some(FunctionMetadataTypes::FinfoTiknibCombo(
                                                    metadata_file.function_info.unwrap(),
                                                ));
                                        } else {
                                            metadata = None
                                        }

                                        AGCJFile {
                                            filename: PathBuf::from(filepath),
                                            function_call_graphs: None,
                                            output_path: output_path.to_owned(),
                                            function_metadata: metadata,
                                            include_unk: *include_unk,
                                        }
                                    };
                                    debug!("Attempting to load {:?}", file.filename);
                                    file.load_and_deserialize()
                                        .expect("Unable to load and deserialize JSON");

                                    file.process_based_on_graph_data_type(
                                        graph_data_type,
                                        with_features,
                                        metadata_type.clone(),
                                    );
                                    info!(
                                        "Finished generating cgs + metadata for {:?}",
                                        file.filename
                                    );
                                } else {
                                    info!(
                                        "Skipping {} as already exists",
                                        full_output_path.to_string_lossy()
                                    )
                                }
                            },
                        );
                    }
                }
            }
            GenerateSubCommands::Metadata {
                input_path,
                output_path,
                data_source_type,
                extended,
            } => {
                if data_source_type == "finfo" {
                    validate_input(input_path, "metadata_finfo");
                    let mut file = AFIJFile {
                        filename: input_path.to_owned(),
                        function_info: None,
                        output_path: output_path.to_owned(),
                    };
                    info!("Generating function metadata subsets");
                    file.load_and_deserialize()
                        .expect("Unable to load and desearilize JSON");
                    info!("Successfully loaded JSON");
                    file.subset_and_save(*extended);
                    info!("Generation complete");
                } else if data_source_type == "tiknib" {
                    warn!("This currently only supports making TikNib features for single files");

                    if input_path.is_file() {
                        validate_input(input_path, "metadata_tiknib");
                        let mut file = AGFJFile {
                            functions: None,
                            filename: input_path.to_owned(),
                            output_path: output_path.to_owned(),
                            min_blocks: 1, // Dummy
                            feature_type: None,
                            architecture: None,
                            reg_norm: false, // Dummy
                        };

                        file.load_and_deserialize().expect("Unable to load data");
                        file.tiknib_func_level_feature_gen()
                    } else {
                        let file_paths_vec =
                            get_json_paths_from_dir(input_path, Some("_cfg".to_string()));

                        file_paths_vec.par_iter().for_each(|filepath| {
                            let mut file = AGFJFile {
                                functions: None,
                                filename: filepath.to_owned().parse().unwrap(),
                                output_path: output_path.to_owned(),
                                min_blocks: 1, // Dummy
                                feature_type: None,
                                architecture: None,
                                reg_norm: false, // Dummy
                            };

                            file.load_and_deserialize().expect("Unable to load data");
                            file.tiknib_func_level_feature_gen()
                        });
                    }
                }
            }
            GenerateSubCommands::Combos {
                input_path,
                output_path,
                combo_type,
                num_threads,
            } => {
                warn!("This feature is experimental and should be used with caution!");
                let combo_job = ComboJob::new(combo_type, input_path, output_path);

                if combo_job.is_ok() {
                    let combo_job = combo_job.unwrap();
                    rayon::ThreadPoolBuilder::new()
                        .num_threads(*num_threads)
                        .build_global()
                        .unwrap();

                    match combo_job.combo_type {
                        combos::ComboTypes::FinfoTikib => combo_job.process_finfo_tiknib(),
                    }
                } else {
                    error!("Invalid combo type: {}", combo_type);
                    exit(1)
                }
            }
            GenerateSubCommands::Nlp {
                path,
                instruction_type,
                min_blocks,
                data_out_path,
                output_format,
                random_walk,
                reg_norm,
                pairs,
                pcode_file_format,
            } => {
                if !path.exists() {
                    error!("The path {:?} does not exist!", path);
                    exit(1)
                }

                let instruction_type = match instruction_type.as_str() {
                    "esil" => InstructionMode::ESIL,
                    "disasm" => InstructionMode::Disasm,
                    "pcode" => InstructionMode::PCode,
                    _ => InstructionMode::Invalid,
                };

                if instruction_type == InstructionMode::PCode && pcode_file_format.is_none() {
                    error!("--pcode-file-format is required when processed PCode")
                }

                if instruction_type == InstructionMode::Invalid {
                    error!("Invalid instruction mode: {:?}", instruction_type);
                    exit(1)
                }

                let format_type = match output_format.as_str() {
                    "single" => FormatMode::SingleInstruction,
                    "funcstring" => FormatMode::FuncAsString,
                    _ => FormatMode::Invalid,
                };

                if format_type == FormatMode::FuncAsString && *pairs {
                    error!("The pairs option is not supported for 'funcstring' format. Only 'single' is supported");
                    exit(1)
                };

                if format_type == FormatMode::Invalid {
                    error!("Invalid format type: {:?}", format_type);
                    exit(1)
                }

                if Path::new(path).is_file() {
                    info!("Single file found");
                    validate_input(path, "nlp");
                    match instruction_type {
                        InstructionMode::ESIL | InstructionMode::Disasm => {
                            let file = AGFJFile {
                                functions: None,
                                filename: path.to_owned(),
                                output_path: data_out_path.to_owned(),
                                min_blocks: *min_blocks,
                                feature_type: None,
                                architecture: None,
                                reg_norm: *reg_norm,
                            };

                            file.execute_data_generation(
                                format_type,
                                instruction_type,
                                random_walk,
                                *pairs,
                            )
                        }
                        InstructionMode::PCode => {
                            let pcode_file_type = match pcode_file_format.as_ref().unwrap().as_str()
                            {
                                "pcode-func" => PCodeFileTypes::PCodeJsonFile,
                                "pcode-bb" => PCodeFileTypes::PCodeWithBBFile,
                                _ => unreachable!("Invalid PCode file type"),
                            };

                            let mut file = PCodeFile {
                                filename: path.to_owned(),
                                pcode_obj: None,
                                output_path: data_out_path.to_owned(),
                                min_blocks: Option::from(*min_blocks),
                                instruction_pairs: *pairs,
                                format_type,
                                pcode_file_type,
                            };

                            file.load_and_deserialize()
                                .expect("Unable to load PCode file");
                            file.execute_data_generation();
                        }
                        _ => {
                            error!(
                                "Invalid instruction type: {:?}. Exiting..",
                                instruction_type
                            );
                            exit(1)
                        }
                    }
                } else {
                    info!("Multiple files found. Will parallel process.");
                    let file_paths_vec = get_json_paths_from_dir(path, Some("_cfg".to_string()));
                    info!(
                        "{} files found. Beginning Processing.",
                        file_paths_vec.len()
                    );
                    for file in file_paths_vec.iter().progress() {
                        let file = AGFJFile {
                            functions: None,
                            filename: PathBuf::from(file),
                            output_path: data_out_path.to_owned(),
                            min_blocks: *min_blocks,
                            feature_type: None,
                            architecture: None,
                            reg_norm: *reg_norm,
                        };
                        file.execute_data_generation(
                            format_type,
                            instruction_type,
                            random_walk,
                            *pairs,
                        )
                    }
                }
            }
            GenerateSubCommands::Tokeniser {
                data,
                output_name,
                vocab_size,
                tokeniser_type,
            } => {
                let t_type = match tokeniser_type.as_str() {
                    "bpe" => TokeniserType::CommaBPE,
                    "byte-bpe" => TokeniserType::ByteBPE,
                    _ => TokeniserType::Invalid,
                };
                if t_type == TokeniserType::CommaBPE {
                    todo!("not implemented")
                } else if t_type == TokeniserType::ByteBPE {
                    train_byte_bpe_tokeniser(data, output_name, *vocab_size).unwrap();
                } else {
                    println!("Invalid tokeniser type - Please choose either bpe or byte-bpe");
                    exit(1)
                }
            }
        },
        Commands::Extract {
            fpath,
            output_dir,
            modes,
            num_threads,
            debug,
            extended_analysis,
            use_curl_pdb,
            with_annotations,
        } => {
            info!("Creating extraction job with {} modes", modes.len());
            if !output_dir.exists() {
                error!("Output directory does not exist - {:?}. Create the directory and re-run again. Exiting...", output_dir);
                exit(1)
            }

            // Create a single extraction job with all modes
            let job = ExtractionJob::new(
                fpath,
                output_dir,
                modes,
                debug,
                extended_analysis,
                use_curl_pdb,
                with_annotations,
            )
            .unwrap_or_else(|e| {
                error!("Failed to create extraction job: {}", e);
                exit(1);
            });

            info!(
                "Created extraction job with {} job types",
                job.job_types.len()
            );

            if job.input_path_type == PathType::Dir {
                info!("Directory found - will parallel process");

                info!("Creating thread pool with {} threads", num_threads);
                rayon::ThreadPoolBuilder::new()
                    .num_threads(*num_threads)
                    .build_global()
                    .unwrap();

                // Process all files in parallel, each file processes all modes with a single r2pipe
                job.files_to_be_processed
                    .par_iter()
                    .progress()
                    .for_each(|path| path.process_all_modes());
            } else if job.input_path_type == PathType::File {
                info!("Single file found");

                // Process single file with all modes using a single r2pipe instance
                job.files_to_be_processed[0].process_all_modes();

                info!(
                    "Extraction complete for {:?} with {} modes",
                    fpath,
                    modes.len()
                );
            }

            info!("All extractions completed");
        }

        #[cfg(feature = "inference")]
        Commands::Inference {
            sequence,
            tokeniser_fp,
            model_fp,
            mean_pool,
        } => {
            inference(
                tokeniser_fp,
                &Some(model_fp.to_string()),
                mean_pool,
                sequence,
            );
        }
        Commands::Dedup { subcommands } => match subcommands {
            DedupSubCommands::Cgs {
                filename,
                output_path,
                num_threads,
                filepath_format,
                node_feature_type,
                inplace,
            } => {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(*num_threads)
                    .build_global()
                    .unwrap();

                if Path::new(filename).exists() {
                    let node_feature_type = CallGraphNodeFeatureType::new(node_feature_type);
                    info!("Starting duplication process for One Hop Call Graphs");
                    let corpus =
                        CGCorpus::new(filename, output_path, filepath_format, node_feature_type)
                            .unwrap();
                    if *inplace {
                        corpus.process_corpus_inplace();
                    } else {
                        corpus.process_corpus();
                    }
                } else {
                    error!("Filename provided does not exist! - {:?}", filename)
                }
            }
            DedupSubCommands::Esil {
                filename,
                print_stats,
                just_stats,
                just_hash_value,
                num_threads,
                output_path,
            } => {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(*num_threads)
                    .build_global()
                    .unwrap();

                warn!("This only supports the Cisco Talos Binary Sim Dataset naming convention");
                let corpus = EsilFuncStringCorpus::new(filename, output_path).unwrap();
                corpus.uniq_binaries.par_iter().progress().for_each(|name| {
                    corpus.dedup_subset(name, *print_stats, *just_stats, *just_hash_value)
                });
            }
        },
    }
}
