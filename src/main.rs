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
pub mod consts;
pub mod dedup;
pub mod errors;
pub mod extract;
pub mod files;
#[cfg(feature = "inference")]
pub mod inference;
pub mod networkx;
pub mod normalisation;
pub mod processors;
pub mod tokeniser;
pub mod utils;

use crate::dedup::{EsilFuncStringCorpus, OneHopCGCorpus};
use crate::extract::ExtractionJobType;
use crate::files::{AFIJFile, AGCJFile};
use crate::tokeniser::{train_byte_bpe_tokeniser, TokeniserType};
use crate::utils::get_save_file_path;
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

#[derive(PartialEq)]
enum DataType {
    Cfg,
    Cg,
    OneHopCg,
    CgWithCallers,
    OneHopCgWithcallers,
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
        path: String,

        /// The target data type
        #[arg(short, long, value_name = "DATA_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["cfg", "cg", "onehopcg", "cgcallers", "onehopcgcallers"])
        .map(|s| s.parse::<String>().unwrap()),)]
        data_type: String,

        /// The output path for the processed Networkx graphs (1 per function)
        #[arg(short, long, value_name = "OUTPUT")]
        output_path: String,

        /// The type of features to generate per basic block (node)
        #[arg(short, long, value_name = "FEATURE_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["gemini", "discovre", "dgis"])
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

        /// Toggle for call graphs to include AFIJ feature subsets
        #[arg(long, default_value = "false")]
        with_features: bool,

        /// Filepath to the AFIJ function metadata
        #[arg(long)]
        metadata_path: Option<String>,

        /// Include unknown functions
        #[arg(long, default_value = "false")]
        include_unk: bool,
    },
    /// Generate NLP data from extracted data
    Nlp {
        /// The path to a JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "FILENAME")]
        path: String,

        /// The type of data to be generated
        #[arg(short, long, value_name = "DATA_TYPE", value_parser = clap::builder::PossibleValuesParser::new(["esil", "disasm"])
        .map(|s| s.parse::<String>().unwrap()),)]
        instruction_type: String,

        /// The min number of basic blocks. Any CFG's below this number will be skipped
        #[arg(long, default_value = "5")]
        min_blocks: u16,

        /// The output path for the processed data
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        data_out_path: String,

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
    },
    /// Generate metadata/feature subsets from extracted data
    Metadata {
        /// The path to an afji JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "INPUT_PATH")]
        input_path: String,
        /// The path for the generated output
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: String,
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
}

#[derive(Subcommand)]
enum Commands {
    /// Get summary information for a binary
    #[cfg(feature = "goblin")]
    Info {
        /// The path to the target binary
        #[arg(short, long, value_name = "FILENAME")]
        path: Option<String>,
    },
    /// Generate processed data from extracted raw data
    Generate {
        #[command(subcommand)]
        subcommands: GenerateSubCommands,
    },
    /// Extract raw data from input binaries
    Extract {
        /// The path to the dir or binary to be processed
        #[arg(short, long, value_name = "DIR")]
        fpath: String,

        /// The path for the output directory
        #[arg(short, long, value_name = "DIR")]
        output_dir: String,

        /// The extraction mode
        #[arg(short, long, value_name = "EXTRACT_MODE", value_parser = clap::builder::PossibleValuesParser::new(["finfo", "reg", "cfg", "xrefs","cg"])
        .map(|s| s.parse::<String>().unwrap()),)]
        mode: String,

        /// The number of threads Rayon can use when parallel processing
        #[arg(short, long, value_name = "NUM_THREADS", default_value = "2")]
        num_threads: usize,

        #[arg(long, default_value = "false")]
        debug: bool,
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
        /// The filename to dedup
        #[arg(short, long, value_name = "FILENAME")]
        filename: String,

        /// Type of dedup
        #[arg(short, long, value_name = "TYPE", value_parser = clap::builder::PossibleValuesParser::new(["esilfstr", "onehopcgs"])
        .map(|s| s.parse::<String>().unwrap()))]
        datatype: String,

        /// Output path to save dedup corpus - Only works for onehopcgs atm
        #[arg(short, long, value_name = "OUTPUT_PATH")]
        output_path: String,

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
        .filter_or("LOG_LEVEL", "info")
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
            } => {
                let graph_data_type = match graph_type.as_str() {
                    "cfg" => DataType::Cfg,
                    "cg" => DataType::Cg,
                    "onehopcg" => DataType::OneHopCg,
                    "cgcallers" => DataType::CgWithCallers,
                    "onehopcgcallers" => DataType::OneHopCgWithcallers,
                    _ => DataType::Invalid,
                };

                if graph_data_type == DataType::Cfg && *with_features {
                    warn!("The 'with_features' toggle is set but is not support for CFG generation. Will ignore.")
                };

                if !Path::new(path).exists() {
                    error!("{} does not exist!", path);
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
                            #[cfg(feature = "inference")]
                            "embed" => FeatureType::ModelEmbedded,
                            _ => FeatureType::Invalid,
                        };

                        if feature_vec_type == FeatureType::Invalid {
                            warn!("Invalid feature type: {}", feature_type.as_ref().unwrap());
                            exit(1)
                        } else if feature_vec_type == FeatureType::Gemini
                            || feature_vec_type == FeatureType::DiscovRE
                            || feature_vec_type == FeatureType::DGIS
                        {
                            info!(
                                "Creating graphs with {:?} feature vectors.",
                                feature_vec_type
                            );

                            if Path::new(path).is_file() {
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
                                        agfj_graph_statistical_features(
                                            file.path().to_str().unwrap(),
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
                                    println!("Both Tokeniser and Model filespaths are needed");
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
                        }
                    } else {
                        error!("--feature-type/-f is required for creating CFG's")
                    }
                } else {
                    // If its only one file
                    if Path::new(path).is_file() {
                        let mut file = if *with_features {
                            if metadata_path.is_none() {
                                error!("with features active - require --metadata-path argument");
                                exit(1)
                            };
                            let mut metadata = AFIJFile {
                                filename: metadata_path.clone().unwrap(),
                                function_info: None,
                                output_path: "".to_string(),
                            };
                            metadata
                                .load_and_deserialize()
                                .expect("Unable to load file");
                            let metadata_subset = metadata.subset();
                            AGCJFile {
                                filename: path.to_owned(),
                                function_call_graphs: None,
                                output_path: output_path.to_owned(),
                                function_metadata: Some(metadata_subset),
                                include_unk: *include_unk,
                            }
                        } else {
                            AGCJFile {
                                filename: path.to_owned(),
                                function_call_graphs: None,
                                output_path: output_path.to_owned(),
                                function_metadata: None,
                                include_unk: *include_unk,
                            }
                        };
                        file.load_and_deserialize()
                            .expect("Unable to load and desearilize JSON");
                        if graph_data_type == DataType::Cg {
                            for fcg in file.function_call_graphs.as_ref().unwrap() {
                                fcg.to_petgraph(
                                    &file,
                                    &file.output_path,
                                    &file.filename,
                                    with_features,
                                    &file.include_unk,
                                );
                            }
                        } else if graph_data_type == DataType::OneHopCg {
                            for fcg in file.function_call_graphs.as_ref().unwrap() {
                                fcg.one_hop_to_petgraph(
                                    &file,
                                    &file.output_path,
                                    &file.filename,
                                    with_features,
                                    &file.include_unk,
                                );
                            }
                        } else if graph_data_type == DataType::CgWithCallers {
                            for fcg in file.function_call_graphs.as_ref().unwrap() {
                                fcg.to_petgraph_with_callers(
                                    &file,
                                    &file.output_path,
                                    &file.filename,
                                    with_features,
                                    &file.include_unk,
                                );
                            }
                        } else if graph_data_type == DataType::OneHopCgWithcallers {
                            for fcg in file.function_call_graphs.as_ref().unwrap() {
                                fcg.one_hop_to_petgraph_with_callers(
                                    &file,
                                    &file.output_path,
                                    &file.filename,
                                    with_features,
                                    &file.include_unk,
                                );
                            }
                        }
                    } else {
                        debug!("Multiple files found");

                        if metadata_path.is_none() & with_features {
                            error!("with features active - require --metadata-path argument");
                            exit(1)
                        };

                        let mut file_paths_vec =
                            get_json_paths_from_dir(path, Some("_cg".to_string()));
                        info!(
                            "{} files found. Beginning Processing.",
                            file_paths_vec.len()
                        );
                        // if without metadata
                        if !with_features {
                            debug!("Creating call graphs without any node features");

                            file_paths_vec.par_iter().for_each(|path| {
                                let suffix = graph_type.to_owned().to_string();
                                let full_output_path = PathBuf::from(get_save_file_path(
                                    path,
                                    output_path,
                                    Some(suffix),
                                ));
                                if !full_output_path.is_dir() {
                                    let mut file = AGCJFile {
                                        filename: path.to_owned(),
                                        function_call_graphs: None,
                                        output_path: output_path.to_owned(),
                                        function_metadata: None,
                                        include_unk: *include_unk,
                                    };
                                    debug!("Proceissing {}", file.filename);
                                    file.load_and_deserialize()
                                        .expect("Unable to load and desearilize JSON");

                                    if graph_data_type == DataType::Cg {
                                        for fcg in file.function_call_graphs.as_ref().unwrap() {
                                            fcg.to_petgraph(
                                                &file,
                                                &file.output_path,
                                                &file.filename,
                                                with_features,
                                                &file.include_unk,
                                            );
                                        }
                                    } else if graph_data_type == DataType::OneHopCg {
                                        for fcg in file.function_call_graphs.as_ref().unwrap() {
                                            fcg.one_hop_to_petgraph(
                                                &file,
                                                &file.output_path,
                                                &file.filename,
                                                with_features,
                                                &file.include_unk,
                                            );
                                        }
                                    } else if graph_data_type == DataType::CgWithCallers {
                                        for fcg in file.function_call_graphs.as_ref().unwrap() {
                                            fcg.to_petgraph_with_callers(
                                                &file,
                                                &file.output_path,
                                                &file.filename,
                                                with_features,
                                                &file.include_unk,
                                            );
                                        }
                                    } else if graph_data_type == DataType::OneHopCgWithcallers {
                                        for fcg in file.function_call_graphs.as_ref().unwrap() {
                                            fcg.one_hop_to_petgraph_with_callers(
                                                &file,
                                                &file.output_path,
                                                &file.filename,
                                                with_features,
                                                &file.include_unk,
                                            );
                                        }
                                    }
                                } else {
                                    info!(
                                        "Skipping {} as already exists",
                                        full_output_path.to_string_lossy()
                                    )
                                }
                            })
                        } else {
                            debug!("Creating call graphs with node features");
                            debug!("Getting metadata file paths");
                            // its more than one file
                            if metadata_path.is_none() {
                                error!("with features active - require --metadata-path argument");
                                exit(1)
                            };

                            let mut metadata_paths_vec = get_json_paths_from_dir(
                                metadata_path.as_ref().unwrap(),
                                Some("finfo".to_string()),
                            );

                            file_paths_vec.sort();
                            metadata_paths_vec.sort();

                            assert_eq!(file_paths_vec.len(), metadata_paths_vec.len());
                            let combined_cgs_metadata = file_paths_vec
                                .into_iter()
                                .zip(metadata_paths_vec)
                                .collect::<Vec<_>>();

                            combined_cgs_metadata.par_iter().for_each(|tup| {
                                let suffix = format!("{}-meta", graph_type.to_owned());
                                let full_output_path =
                                    PathBuf::from(get_save_file_path(&tup.0, output_path, Some(suffix)));
                                if !full_output_path.is_dir() {
                                    let mut file = {
                                        let mut metadata = AFIJFile {
                                            filename: tup.1.clone(),
                                            function_info: None,
                                            output_path: "".to_string(),
                                        };
                                        debug!("Attempting to load metadata file: {}", tup.1);
                                        metadata
                                            .load_and_deserialize()
                                            .expect("Unable to load assocaited metadata file");
                                        let metadata_subset = metadata.subset();
                                        AGCJFile {
                                            filename: tup.0.to_owned(),
                                            function_call_graphs: None,
                                            output_path: output_path.to_owned(),
                                            function_metadata: Some(metadata_subset),
                                            include_unk: *include_unk,
                                        }
                                    };
                                    debug!("Attempting to load {}", file.filename);
                                    file.load_and_deserialize()
                                        .expect("Unable to load and desearilize JSON");

                                    if graph_data_type == DataType::Cg {
                                        debug!("Generating call graphs using loaded cgs + metadata");
                                        for fcg in file.function_call_graphs.as_ref().unwrap() {
                                            fcg.to_petgraph(
                                                &file,
                                                &file.output_path,
                                                &file.filename,
                                                with_features,
                                                &file.include_unk
                                            );
                                        }
                                } else if graph_data_type == DataType::OneHopCg {
                                    debug!("Generating one hop call graphs using loaded cgs + metadata");
                                    for fcg in file.function_call_graphs.as_ref().unwrap() {
                                        fcg.one_hop_to_petgraph(&file, &file.output_path, &file.filename, with_features, &file.include_unk);
                                    }
                                } else if graph_data_type == DataType::CgWithCallers {
                                    debug!("Generating call graphs with callers using loaded cgs + metadata");
                                    for fcg in file.function_call_graphs.as_ref().unwrap() {
                                        fcg.to_petgraph_with_callers(
                                            &file,
                                            &file.output_path,
                                            &file.filename,
                                            with_features,
                                            &file.include_unk
                                        );
                                    }
                                } else if graph_data_type == DataType::OneHopCgWithcallers {
                                    debug!("Generating one hop call graphs with callers using loaded cgs + metadata");
                                    for fcg in file.function_call_graphs.as_ref().unwrap() {
                                        fcg.one_hop_to_petgraph_with_callers(
                                            &file,
                                            &file.output_path,
                                            &file.filename,
                                            with_features,
                                            &file.include_unk
                                        );
                                    }
                                }
                                debug!("Finished generating cgs + metadata for {}", file.filename);
                            } else {
                                    info!("Skipping {} as already exists", full_output_path.to_string_lossy())
                                }});
                        }
                    }
                }
            }
            GenerateSubCommands::Metadata {
                input_path,
                output_path,
            } => {
                let mut file = AFIJFile {
                    filename: input_path.to_owned(),
                    function_info: None,
                    output_path: output_path.to_owned(),
                };
                info!("Generating function metadata subsets");
                file.load_and_deserialize()
                    .expect("Unable to load and desearilize JSON");
                info!("Successfully loaded JSON");
                file.subset_and_save();
                info!("Generation complete");
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
            } => {
                let instruction_type = match instruction_type.as_str() {
                    "esil" => InstructionMode::ESIL,
                    "disasm" => InstructionMode::Disasm,
                    _ => InstructionMode::Invalid,
                };

                if instruction_type == InstructionMode::Invalid {
                    error!("Invalid instruction mode: {:?}", instruction_type);
                    exit(1)
                }

                let format_type = match output_format.as_str() {
                    "single" => FormatMode::SingleInstruction,
                    "funcstring" => FormatMode::FuncAsString,
                    _ => FormatMode::Invalid,
                };

                if format_type == FormatMode::Invalid {
                    error!("Invalid format type: {:?}", format_type);
                    exit(1)
                }

                if Path::new(path).is_file() {
                    info!("Single file found");
                    let file = AGFJFile {
                        functions: None,
                        filename: path.to_owned(),
                        output_path: data_out_path.to_string(),
                        min_blocks: *min_blocks,
                        feature_type: None,
                        architecture: None,
                        reg_norm: *reg_norm,
                    };

                    file.execute_data_generation(format_type, instruction_type, random_walk, *pairs)
                } else {
                    info!("Multiple files found. Will parallel process.");
                    let file_paths_vec = get_json_paths_from_dir(path, None);
                    info!(
                        "{} files found. Beginning Processing.",
                        file_paths_vec.len()
                    );
                    for file in file_paths_vec.iter().progress() {
                        let file = AGFJFile {
                            functions: None,
                            filename: file.to_string(),
                            output_path: data_out_path.to_string(),
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
            mode,
            num_threads,
            debug,
        } => {
            info!("Creating extraction job");
            let job = ExtractionJob::new(fpath, output_dir, mode).unwrap();

            if job.input_path_type == PathType::Dir {
                info!("Directory found - will parallel process");

                info!("Creating threadpool with {} threads ", num_threads);
                rayon::ThreadPoolBuilder::new()
                    .num_threads(*num_threads)
                    .build_global()
                    .unwrap();

                if job.job_type == ExtractionJobType::CFG {
                    info!("Extraction Job Type: CFG");
                    info!("Starting Parallel generation.");
                    #[allow(clippy::redundant_closure)]
                    job.files_to_be_processed
                        .par_iter()
                        .progress()
                        .for_each(|path| path.extract_func_cfgs(debug));
                } else if job.job_type == ExtractionJobType::RegisterBehaviour {
                    info!("Extraction Job Type: Register Behaviour");
                    info!("Starting Parallel generation.");
                    #[allow(clippy::redundant_closure)]
                    job.files_to_be_processed
                        .par_iter()
                        .progress()
                        .for_each(|path| path.extract_register_behaviour(debug));
                } else if job.job_type == ExtractionJobType::FunctionXrefs {
                    info!("Extraction Job Type: Function Xrefs");
                    info!("Starting Parallel generation.");
                    #[allow(clippy::redundant_closure)]
                    job.files_to_be_processed
                        .par_iter()
                        .progress()
                        .for_each(|path| path.extract_function_xrefs(debug));
                } else if job.job_type == ExtractionJobType::CallGraphs {
                    info!("Extraction Job Type: Call Graphs");
                    info!("Starting Parallel generation.");
                    #[allow(clippy::redundant_closure)]
                    job.files_to_be_processed
                        .par_iter()
                        .progress()
                        .for_each(|path| path.extract_function_call_graphs(debug));
                } else if job.job_type == ExtractionJobType::FuncInfo {
                    info!("Extraction Job Type: Function Info");
                    info!("Starting Parallel generation.");
                    #[allow(clippy::redundant_closure)]
                    job.files_to_be_processed
                        .par_iter()
                        .progress()
                        .for_each(|path| path.extract_function_info(debug));
                }
            } else if job.input_path_type == PathType::File {
                info!("Single file found");
                if job.job_type == ExtractionJobType::CFG {
                    info!("Extraction Job Type: CFG");
                    job.files_to_be_processed[0].extract_func_cfgs(debug);
                } else if job.job_type == ExtractionJobType::RegisterBehaviour {
                    info!("Extraction Job Type: Register Behaviour");
                    job.files_to_be_processed[0].extract_register_behaviour(debug)
                } else if job.job_type == ExtractionJobType::FunctionXrefs {
                    info!("Extraction Job type: Function Xrefs");
                    job.files_to_be_processed[0].extract_function_xrefs(debug)
                } else if job.job_type == ExtractionJobType::CallGraphs {
                    info!("Extraction Job type: Function Call Graphs");
                    job.files_to_be_processed[0].extract_function_call_graphs(debug)
                } else if job.job_type == ExtractionJobType::FuncInfo {
                    info!("Extraction Job type: Function Info");
                    job.files_to_be_processed[0].extract_function_info(debug)
                }
                info!("Extraction complete for {}", fpath)
            }
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
        Commands::Dedup {
            filename,
            datatype,
            output_path,
            print_stats,
            just_stats,
            num_threads,
            just_hash_value,
        } => {
            if datatype == "esilfstr" {
                warn!("This only supports the Cisco Talos Binary Sim Dataset naming convention");
                rayon::ThreadPoolBuilder::new()
                    .num_threads(*num_threads)
                    .build_global()
                    .unwrap();
                let corpus = EsilFuncStringCorpus::new(filename).unwrap();
                corpus.uniq_binaries.par_iter().progress().for_each(|name| {
                    corpus.dedup_subset(name, *print_stats, *just_stats, *just_hash_value)
                });
            } else if datatype == "onehopcgs" {
                warn!("This only supports the Cisco Talos Binary Sim Dataset naming convention");
                if Path::new(filename).exists() {
                    info!("Starting duplication process for One Hop Call Graphs");
                    let corpus = OneHopCGCorpus::new(filename, output_path).unwrap();
                    corpus.process_corpus();
                } else {
                    error!("Filename provided does not exist! - {}", filename)
                }
            }
        }
    }
}
