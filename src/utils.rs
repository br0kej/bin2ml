use std::path::Path;

pub fn get_save_file_path(path: &str, output_path: &String) -> String {
    let file_name = Path::new(path).file_stem().unwrap();

    let full_output_path = format!(
        "{}/{}",
        output_path.strip_suffix('/').unwrap_or(output_path),
        String::from(file_name.to_str().unwrap())
    );

    full_output_path
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
