use tch;
use tch::{CModule, Device, Tensor};
use tokenizers::tokenizer::{Result, Tokenizer};

#[derive(Debug)]
pub struct InferenceJob {
    pub device: Device,
    tokeniser: Tokenizer,
    model: Option<CModule>,
    mean_pool: bool,
    pub embed_dim: i64,
}

impl InferenceJob {
    pub fn new(
        tokeniser_fp: &str,
        model_fp: &Option<String>,
        mean_pool: bool,
        embed_dim: &Option<i64>,
    ) -> Result<InferenceJob> {
        // This is hard codes to always default to CPU inference - GPU isn't working
        let device = tch::Device::Cpu;
        let tokeniser = Tokenizer::from_file(tokeniser_fp).expect("Unable to load {}");
        let model: Option<_> = if model_fp.is_some() {
            let mut model = tch::CModule::load_on_device(model_fp.as_ref().unwrap(), device)
                .expect("Unable to load model file!");
            model.set_eval();
            Some(model)
        } else {
            None
        };

        let embed_dim: i64 = if embed_dim.is_none() {
            0
        } else {
            embed_dim.unwrap()
        };
        Ok(InferenceJob {
            device,
            tokeniser,
            model,
            mean_pool,
            embed_dim: embed_dim.to_owned(),
        })
    }

    // ########################### DATA PREP FUNCTIONS ###########################

    // This function encodes a given sequence, gets the corresponding
    // integer id's and then casts the vectors from u32's to i32's
    pub fn encode(&self, sequence: &str) -> Vec<i32> {
        let binding = self
            .tokeniser
            .encode(sequence, true)
            .expect("Failed to encode");
        let encoding = binding.get_ids();
        let encoding: Vec<i32> = encoding.iter().map(|&p| p as i32).collect();
        encoding
    }

    // This function does the same as the above but also converst the Vec<i32>'s into
    // a tch-rs tensor and reshapes ready for inputting into a model
    fn encode_and_tensorify(&self, sequence: &str) -> tch::Tensor {
        let encoding: Vec<i32> = self.encode(sequence);
        let tensor: Tensor = Tensor::of_slice(&encoding)
            .reshape(&[1, -1])
            .to_device(self.device);

        tensor
    }

    fn get_attention_mask(&self, length: i64) -> tch::Tensor {
        Tensor::ones(&[1, length], (tch::Kind::Int, self.device))
    }

    // ########################### INFERENCE FUNCTIONS ###########################

    pub fn embed(&self, sequence: &str) -> tch::Tensor {
        let feature_tensor = self.encode_and_tensorify(sequence);
        let tensor_dim = feature_tensor.size();
        let atten_mask = self.get_attention_mask(tensor_dim[1]);

        let model_output = self
            .model
            .as_ref()
            .unwrap()
            .forward_ts(&[feature_tensor, atten_mask])
            .expect("Failed to run forward_ts");

        if self.mean_pool {
            let pooled_output = model_output.mean_dim(Some([1].as_slice()), true, tch::Kind::Float);
            pooled_output
        } else {
            model_output
        }
    }
}

pub fn inference(tokeniser_fp: &str, model_fp: &Option<String>, mean_pool: &bool, sequence: &str) {
    let infer = InferenceJob::new(tokeniser_fp, model_fp, *mean_pool, &Some(128)).unwrap();

    let out = infer.embed(sequence);
    println!("{:?}", out)
}
