use proc_maps::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;

#[derive(Serialize, Deserialize, Debug)]
struct Frame {
    method_idx: usize,
    file_idx: usize,
}

#[derive(Serialize, Deserialize, Debug)]
struct Sample {
    stack: Vec<Frame>,
    comm: String, // this could be interned, too
    pid: Pid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Profile {
    #[serde(skip)]
    symbol_id_map: HashMap<String, u32>,
    symbols: Vec<String>,
    samples: Vec<Sample>,
    // stats
    samples_count: u32,
    errors_count: u32, // split by error type
}

impl Profile {
    pub fn new() -> Self {
        Profile {
            symbol_id_map: HashMap::new(),
            symbols: Vec::new(),
            samples: Vec::new(),
            samples_count: 0,
            errors_count: 0,
        }
    }

    pub fn add_sample(&mut self, pid: Pid, comm: String, stack: Vec<(String, String)>) {
        let mut sample = Sample {
            stack: Vec::new(),
            comm: comm,
            pid: pid,
        };

        for (method, path) in stack {
            sample.stack.push(Frame {
                method_idx: self.index_for(method),
                file_idx: self.index_for(path),
            });
        }

        self.samples_count += 1;
        self.samples.push(sample);
    }

    pub fn add_error(&mut self) {
        self.errors_count += 1;
    }

    fn index_for(&mut self, name: String) -> usize {
        match self.symbol_id_map.get(&name) {
            Some(index) => *index as usize,
            None => {
                let idx = self.symbol_id_map.len();
                self.symbol_id_map
                    .insert(name.clone(), idx.try_into().unwrap());
                self.symbols.push(name);
                idx as usize
            }
        }
    }

    pub fn folded(&self) -> String {
        let mut sample_count = HashMap::new();
        for sample in &self.samples {
            let mut stack = Vec::new();
            for frame in &sample.stack {
                let method_name = &self.symbols[frame.method_idx];
                stack.push(method_name);
            }

            // https://www.reddit.com/r/rust/comments/2xjhli/best_way_to_increment_counter_in_a_map/
            match sample_count.get_mut(&stack) {
                Some(count) => *count += 1,
                None => {
                    sample_count.insert(stack.clone(), 1);
                    ()
                }
            };
        }

        let mut result = String::new();
        for (stack, count) in sample_count {
            // :(

            // https://www.reddit.com/r/rust/comments/6q4uqc/help_whats_the_best_way_to_join_an_iterator_of/
            result += &format!(
                "{} {}\n",
                stack
                    .into_iter()
                    .map(|s| &**s)
                    .collect::<Vec<&str>>()
                    .join(";"),
                count
            );
        }
        result
    }
}
