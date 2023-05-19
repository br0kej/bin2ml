use std::path::PathBuf;
use tokenizers::models::bpe::{BpeTrainerBuilder, BPE};
use tokenizers::normalizers::{strip::Strip, unicode::NFC, utils::Sequence};
use tokenizers::pre_tokenizers::byte_level::ByteLevel;
use tokenizers::{AddedToken, Result, TokenizerBuilder};

#[derive(PartialEq)]
pub enum TokeniserType {
    ByteBPE,
    CommaBPE,
    Invalid,
}

pub fn train_byte_bpe_tokeniser(
    file_or_dir_fp: &String,
    output_path: &String,
    vocab_size: usize,
) -> Result<()> {
    let file_or_dir_fp_path = PathBuf::from(file_or_dir_fp);
    let fps = if file_or_dir_fp_path.is_dir() {
        todo!("Using a directory as files as input to tokeniser generation is currently not supported!")
    } else {
        file_or_dir_fp
    };

    let mut trainer = BpeTrainerBuilder::new()
        .show_progress(true)
        .vocab_size(vocab_size)
        .min_frequency(0)
        .special_tokens(vec![
            AddedToken::from(String::from("<s>"), true),
            AddedToken::from(String::from("<pad>"), true),
            AddedToken::from(String::from("</s>"), true),
            AddedToken::from(String::from("<unk>"), true),
            AddedToken::from(String::from("<mask>"), true),
        ])
        .build();

    let mut tokenizer = TokenizerBuilder::new()
        .with_model(BPE::default())
        .with_normalizer(Some(Sequence::new(vec![
            Strip::new(true, true).into(),
            NFC.into(),
        ])))
        .with_pre_tokenizer(Some(ByteLevel::default()))
        .with_post_processor(Some(ByteLevel::default()))
        .with_decoder(Some(ByteLevel::default()))
        .build()?;

    let pretty = false;
    tokenizer
        .train_from_files(&mut trainer, vec![fps.to_string()])?
        .save(output_path, pretty)?;

    Ok(())
}

/*
pub fn train_comma_bpe_tokeniser(
    file_or_dir_fp: &String,
    output_path: &String,
    vocab_size: usize,
) -> Result<()> {
    let file_or_dir_fp_path = PathBuf::from(file_or_dir_fp);
    let fps = if file_or_dir_fp_path.is_dir() {
        todo!("Using a directory as files as input to tokeniser generation is currently not supported!")
    } else {
        file_or_dir_fp
    };

    let mut trainer = BpeTrainerBuilder::new()
        .show_progress(true)
        .vocab_size(vocab_size)
        .min_frequency(0)
        .special_tokens(vec![
            AddedToken::from(String::from("<s>"), true),
            AddedToken::from(String::from("<pad>"), true),
            AddedToken::from(String::from("</s>"), true),
            AddedToken::from(String::from("<unk>"), true),
            AddedToken::from(String::from("<mask>"), true),
        ])
        .build();

    let mut tokenizer = TokenizerBuilder::new()
        .with_model(BPE::default())
        .with_normalizer(Some(Sequence::new(vec![Strip::new(true, true).into()])))
        .with_pre_tokenizer(Some(CharDelimiterSplit::new(',')))
        .build()?;

    let pretty = false;
    tokenizer
        .train_from_files(&mut trainer, vec![fps.to_string()])?
        .save(output_path, pretty)?;

    Ok(())
}
*/
