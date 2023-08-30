use std::path::Path;
use walkdir::WalkDir;
use std::fs::create_dir_all;

pub fn get_save_file_path(path: &str, output_path: &String, optional_suffix: Option<String>) -> String {
    let file_name = Path::new(path).file_stem().unwrap();

    if optional_suffix.is_none() {
        let full_output_path = format!(
            "{}/{}",
            output_path.strip_suffix('/').unwrap_or(output_path),
            String::from(file_name.to_str().unwrap())
        );
        full_output_path
    } else {
        let full_output_path = format!(
            "{}/{}-{}",
            output_path.strip_suffix('/').unwrap_or(output_path),
            String::from(file_name.to_str().unwrap()),
            optional_suffix.unwrap()
        );
        full_output_path
    }
}

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
