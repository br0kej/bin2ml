use std::fs::create_dir_all;
use std::path::PathBuf;
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
    binary_path: &PathBuf,
    output_path: &PathBuf,
    extension: Option<String>,
    optional_suffix: Option<String>,
    remove_suffix: Option<String>,
) -> PathBuf {

    let extension = if extension.is_some() {
        let extension = extension.unwrap();
        if extension.starts_with(".") {
            extension
        } else {
            format!(".{}", extension)
        }
    } else {
            "".to_string()
        };

    let file_name = binary_path
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .to_string();
    debug!("File Name: {}", file_name);
    let file_name = if let Some(suffix) = remove_suffix {
        file_name.replace(&suffix, "")
    } else {
        file_name
    };

    if optional_suffix.is_none() {
        debug!("No Optional Suffix found");
        let full_output_path = format!(
            "{}/{}{}",
            output_path
                .to_string_lossy()
                .strip_suffix('/')
                .unwrap_or(output_path.as_os_str().to_str().unwrap()),
            file_name,
            extension
        );
        debug!("Full Output Path: {}", full_output_path);
        PathBuf::from(full_output_path)
    } else {
        debug!("Optional Suffix found");
        let full_output_path = format!(
            "{}/{}-{}{}",
            output_path
                .to_string_lossy()
                .strip_suffix('/')
                .unwrap_or(output_path.as_os_str().to_str().unwrap()),
            file_name,
            optional_suffix.unwrap(),
            extension
        );
        debug!("Full Output Path: {}", full_output_path);
        PathBuf::from(full_output_path)
    }
}

/// Get the JSON paths from a directory
///
/// This function takes a path to a directory and traverses all
/// files present within identifying files ending in .json before
/// returning a Vec<String> where each string is an absolute path
/// to a given JSON file
pub fn get_json_paths_from_dir(path: &PathBuf, identifier: Option<String>) -> Vec<String> {
    let mut str_vec: Vec<String> = Vec::new();
    let pattern = if identifier.is_none() {
        ".json".to_string()
    } else {
        format!("{}.json", identifier.unwrap())
    };
    for file in WalkDir::new(path).into_iter().filter_map(|file| file.ok()) {
        if file.metadata().unwrap().is_file()
            && file.file_name().to_string_lossy().ends_with(&pattern)
        {
            let f_string = String::from(<&std::path::Path>::clone(&file.path()).to_str().unwrap());
            str_vec.push(f_string.clone());
        }
    }
    str_vec
}

/// Checks to see if a directory is prsent, if not creates
pub fn check_or_create_dir(full_output_path: &PathBuf) {
    if !full_output_path.is_dir() {
        create_dir_all(full_output_path).expect("Unable to create directory!");
    }
}

/// Average
pub fn average(numbers: Vec<f32>) -> f32 {
    numbers.iter().sum::<f32>() / numbers.len() as f32
}
#[cfg(test)]
mod tests {
    use super::*;

    // TESTS FOR SAVE PATH BUILDING
    #[test]
    fn test_get_save_file_path_1() {
        let path: &PathBuf = &PathBuf::from("test_bin/hello.json");
        let output_path: &PathBuf = &PathBuf::from("processed_data/");
        let output_path = get_save_file_path(path, &output_path, Some("cg".to_string()), None);
        assert_eq!(output_path, PathBuf::from("processed_data/hello-cg"))
    }
    #[test]
    fn test_get_save_file_path_2() {
        let path: &PathBuf = &PathBuf::from("test_bin/extra_dir/hello.json");
        let output_path: &PathBuf = &PathBuf::from("with_more/processed_data/");
        let output = get_save_file_path(path, output_path, None, None);
        assert_eq!(output, PathBuf::from("with_more/processed_data/hello"))
    }
    #[test]
    fn test_get_save_file_path_3() {
        let path: &PathBuf = &PathBuf::from("hello.json");
        let output_path: &PathBuf = &PathBuf::from("processed_data");
        let output = get_save_file_path(path, &output_path, None, None);
        assert_eq!(output, PathBuf::from("processed_data/hello"))
    }

    #[test]
    fn test_get_save_file_path_with_suffix_removal() {
        let path: &PathBuf = &PathBuf::from("hello_cg.json");
        let output_path: &PathBuf = &PathBuf::from("processed_data");
        let output = get_save_file_path(
            path,
            &output_path,
            Some("gcg".to_string()),
            Some("_cg".to_string()),
        );
        assert_eq!(output, PathBuf::from("processed_data/hello-gcg"))
    }
}
