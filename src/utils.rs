use std::fs::create_dir_all;
use std::path::Path;
use walkdir::WalkDir;

/// Formats a save file path
///
/// Given an path to a binary, an output path and an optional suffix
/// this function formats a string which can be used for down stream usage
///
/// The reason an optional suffix has been included is to support a case where there
/// are multiple different types of data which can be generated from a single type
/// of extracted data. An example of this is the call graph data. This can be processed
/// to generate normal call graphs (a function + its callees) or a one hop call graph (a function
/// + its calees + the callees of the callees).
///
/// See agcj.rs for an example of this optional suffix being used
pub fn get_save_file_path(
    binary_path: &str,
    output_path: &String,
    optional_suffix: Option<String>,
) -> String {
    let file_name = Path::new(binary_path)
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_string();

    if optional_suffix.is_none() {
        let full_output_path = format!(
            "{}/{}",
            output_path.strip_suffix('/').unwrap_or(output_path),
            file_name
        );
        full_output_path
    } else {
        let full_output_path = format!(
            "{}/{}-{}",
            output_path.strip_suffix('/').unwrap_or(output_path),
            file_name,
            optional_suffix.unwrap()
        );
        full_output_path
    }
}

/// Get the JSON paths from a directory
///
/// This function takes a path to a directory and traverses all
/// files present within identifying files ending in .json before
/// returning a Vec<String> where each string is an absolute path
/// to a given JSON file
pub fn get_json_paths_from_dir(path: &String) -> Vec<String> {
    let mut str_vec: Vec<String> = Vec::new();
    for file in WalkDir::new(path).into_iter().filter_map(|file| file.ok()) {
        if file.metadata().unwrap().is_file()
            && file.file_name().to_string_lossy().ends_with(".json")
        {
            let f_string = String::from(<&std::path::Path>::clone(&file.path()).to_str().unwrap());
            str_vec.push(f_string.clone());
        }
    }
    str_vec
}

/// Checks to see if a directory is prsent, if not creates
pub fn check_or_create_dir(full_output_path: &String) {
    if !Path::new(full_output_path).is_dir() {
        create_dir_all(full_output_path).expect("Unable to create directory!");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TESTS FOR SAVE PATH BUILDING
    #[test]
    fn test_get_save_file_path_1() {
        let path: &str = "test_bin/hello.json";
        let output_path: String = String::from("processed_data/");
        let output_path = get_save_file_path(path, &output_path);
        assert_eq!(output_path, String::from("processed_data/hello"))
    }
    #[test]
    fn test_get_save_file_path_2() {
        let path: &str = "test_bin/extra_dir/hello.json";
        let output_path: String = String::from("with_more/processed_data/");
        let output = get_save_file_path(path, &output_path);
        assert_eq!(output, String::from("with_more/processed_data/hello"))
    }
    #[test]
    fn test_get_save_file_path_3() {
        let path: &str = "hello.json";
        let output_path: String = String::from("processed_data");
        let output = get_save_file_path(path, &output_path);
        assert_eq!(output, String::from("processed_data/hello"))
    }
}
