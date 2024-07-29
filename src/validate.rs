use std::ffi::OsStr;
use std::path::Path;
use std::process::exit;

pub fn validate_input(filepath: &Path, command: &str) {
    check_file_is_json(filepath);
    check_file_is_expected_type(filepath, command)
}

fn check_file_is_json(filepath: &Path) {
    debug!("Filepath: {}", filepath.display());
    let file_extension = filepath.extension();
    debug!("File extension: {:?}", file_extension);
    if Some(OsStr::new("json")) == file_extension {
        debug!("Found the correct file format!")
    } else {
        error!(
            "Incorrect file type passed. Expected file to end with .json not {}",
            file_extension.unwrap().to_string_lossy()
        );
        exit(1)
    }
}

fn check_file_is_expected_type(filepath: &Path, command: &str) {
    debug!("Filepath: {} Command: {}", filepath.display(), command);
    let filepath_str = filepath.to_str().unwrap_or("");

    let file_type_provided = match filepath_str {
        x if x.contains("_reg.json") => "registers",
        x if x.contains("_xrefs.json") => "crossrefs",
        x if x.contains("_cg.json") => "callgraph",
        x if x.contains("_cfg.json") => "controlflow",
        x if x.contains("_finfo.json") => "function_info",
        x if x.contains("_pcode-func.json") => "pcode",
        x if x.contains("_pcode-bb.json") => "pcode",
        _ => "",
    };

    let valid = match command {
        "cfg" => (file_type_provided == "controlflow") | (file_type_provided == "pcode"),
        "cg" => file_type_provided == "callgraph",
        "metadata_finfo" => file_type_provided == "function_info",
        "metadata_tiknib" => file_type_provided == "controlflow",
        "nlp" => (file_type_provided == "controlflow") | (file_type_provided == "pcode"),
        _ => false,
    };

    if valid {
        debug!("Provided filepath and command pair are valid")
    } else {
        let expected_file_type = match command {
            "cfg" => "controlflow (_cfg.json)",
            "cg" => "callgraph (_cg.json)",
            "metadata_finfo" => "function_info (_finfo.json)",
            "metadata_tiknib" => "controlflow (_cfg.json)",
            "nlp" => "controlflow (_cfg.json)",
            _ => "",
        };

        error!(
            "Incorrect file type and command pair. Got {} ({}) for command {} (expected {})",
            filepath_str, file_type_provided, command, expected_file_type
        );
        exit(1)
    }
}
