// Added to enable format expect's which print
// the error and some extra info
#![allow(clippy::expect_fun_call)]

use clap::{Parser, Subcommand};
#[macro_use]
extern crate log;
use env_logger::Env;
use indicatif::{ParallelProgressIterator, ProgressIterator};
use mimalloc::MiMalloc;
use rayon::iter::ParallelIterator;
use rayon::prelude::IntoParallelRefIterator;
use std::path::Path;
use std::process::exit;
use walkdir::WalkDir;

pub mod agfj;
pub mod bb;
#[cfg(feature = "goblin")]
pub mod binnfo;
pub mod consts;
pub mod dedup;
pub mod extract;
pub mod files;
#[cfg(feature = "inference")]
pub mod inference;
pub mod normalisation;
pub mod processors;
pub mod sample;
pub mod tokeniser;
pub mod utils;

use crate::dedup::EsilFuncStringCorpus;
use crate::extract::ExtractionJobType;
use crate::tokeniser::{train_byte_bpe_tokeniser, TokeniserType};
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

/// Turn binaries into machine learning ready formats
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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
    /// Extract CFG level data from binaries
    Extract {
        /// The path to the dir or binary to be processed
        #[arg(short, long, value_name = "DIR")]
        fpath: String,

        /// The path for the output directory
        #[arg(short, long, value_name = "DIR")]
        output_dir: String,

        /// The extraction mode - Currently only supports 'cfg'
        #[arg(short, long, value_name = "EXTRACT_MODE")]
        mode: String,

        /// The number of threads Rayon can use when parallel processing
        #[arg(short, long, value_name = "NUM_THREADS", default_value = "2")]
        num_threads: usize,

        #[arg(long, default_value = "false")]
        debug: bool,
    },
    /// Generate networkx compatible graphs
    Graph {
        /// The path to a JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "FILENAME")]
        path: String,

        /// The min number of basic blocks. Any CFG's below this number will be skipped
        #[arg(long, default_value = "5")]
        min_blocks: u16,

        /// The output path for the processed Networkx graphs (1 per function)
        #[arg(short, long, value_name = "OUTPUT")]
        output_path: String,

        /// The type of features to generate per basic block (node)
        #[arg(short, long, value_name = "FEATURE_TYPE")]
        feature_type: String,

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
    },
    /// Generate NLP-style datasets
    Nlp {
        /// The path to a JSON file extracted using the <EXTRACT> command
        #[arg(short, long, value_name = "FILENAME")]
        path: String,

        /// The type of data to be generated - Currently supports ['esil', 'disasm']
        #[arg(short, long, value_name = "DATA_TYPE")]
        data_type: String,

        /// The min number of basic blocks. Any CFG's below this number will be skipped
        #[arg(long, default_value = "5")]
        min_blocks: u16,

        /// The output path for the processed data
        #[arg(short, long, value_name = "OUTPUT")]
        output_path: String,

        /// The format of the output data
        #[arg(short, long, value_name = "FORMAT")]
        format: String,

        /// Toggle to determine if blocks are sampled in a random walk nature
        #[arg(long, default_value = "false")]
        random_walk: bool,

        /// Toggle register normalisation
        #[arg(long, default_value = "false")]
        reg_norm: bool,
    },
    /// Generate HuggingFace tokeniser.json files from a corpus (REFACTOR_NEEDED)
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
        hash_just_value: bool,
    },
}

fn main() {
    let env = Env::default()
        .filter_or("MY_LOG_LEVEL", "trace")
        .write_style_or("MY_LOG_STYLE", "always");

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

                // info!("Collection file paths from directory");
                // let str_vec: Vec<String> = job.get_file_paths_dir();

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
                    job.files_to_be_processed.par_iter().progress().for_each(|path| {
                        path.extract_register_behaviour(debug)
                    });
                }
                //info!("Extraction complete. Processed {} files.", str_vec.len())
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
                }
                info!("Extraction complete for {}", fpath)
            }
        }
        Commands::Graph {
            path,
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
        } => {
            let feature_vec_type = match feature_type.as_str() {
                "gemini" => FeatureType::Gemini,
                "discovre" => FeatureType::DiscovRE,
                "dgis" => FeatureType::DGIS,
                "encode" => FeatureType::Encoded,
                #[cfg(feature = "inference")]
                "embed" => FeatureType::ModelEmbedded,
                _ => FeatureType::Invalid,
            };

            if feature_vec_type == FeatureType::Invalid {
                error!("Invalid feature type: {}", feature_type);
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
                    agfj_graph_statistical_features(path, min_blocks, output_path, feature_vec_type)
                } else {
                    info!("Multiple files found. Will parallel process.");
                    for file in WalkDir::new(path).into_iter().filter_map(|file| file.ok()) {
                        if file.path().to_string_lossy().ends_with(".json") {
                            agfj_graph_statistical_features(
                                file.path().to_str().unwrap(),
                                min_blocks,
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
                            min_blocks,
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
        }
        Commands::Nlp {
            path,
            data_type,
            min_blocks,
            output_path,
            format,
            random_walk,
            reg_norm,
        } => {
            let instruction_type = match data_type.as_str() {
                "esil" => InstructionMode::ESIL,
                "disasm" => InstructionMode::Disasm,
                _ => InstructionMode::Invalid,
            };

            if instruction_type == InstructionMode::Invalid {
                error!("Invalid instruction mode: {:?}", data_type);
                exit(1)
            }

            let format_type = match format.as_str() {
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
                    output_path: output_path.to_string(),
                    min_blocks: *min_blocks,
                    feature_type: None,
                    architecture: None,
                    reg_norm: *reg_norm,
                };

                file.execute_data_generation(format_type, instruction_type, random_walk)
            } else {
                info!("Multiple files found. Will parallel process.");
                let file_paths_vec = get_json_paths_from_dir(path);
                info!(
                    "{} files found. Beginning Processing.",
                    file_paths_vec.len()
                );
                for file in file_paths_vec.iter().progress() {
                    let file = AGFJFile {
                        functions: None,
                        filename: file.to_string(),
                        output_path: output_path.to_string(),
                        min_blocks: *min_blocks,
                        feature_type: None,
                        architecture: None,
                        reg_norm: *reg_norm,
                    };
                    file.execute_data_generation(format_type, instruction_type, random_walk)
                }
            }
        }
        Commands::Tokeniser {
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
            print_stats,
            just_stats,
            num_threads,
            hash_just_value,
        } => {
            eprintln!("THIS ONLY SUPPORTS FILES WITH THE FOLLOWING NAMING CONVENTION: <arch>-<compiler-name>-<verion>-<opt-level>_<binary_name>-<datatype>.json");
            rayon::ThreadPoolBuilder::new()
                .num_threads(*num_threads)
                .build_global()
                .unwrap();
            let corpus = EsilFuncStringCorpus::new(filename).unwrap();
            corpus.uniq_binaries.par_iter().progress().for_each(|name| {
                corpus.dedup_subset(name, *print_stats, *just_stats, *hash_just_value)
            });
        }
    }
}
