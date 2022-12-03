use proc_maps::Pid;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::Write;

#[derive(Serialize, Deserialize, Debug)]
struct Frame {
    method_idx: usize,
    file_idx: usize,
    lineno: Option<u32>,
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
}

impl Default for Profile {
    fn default() -> Self {
        Self::new()
    }
}

impl Profile {
    pub fn new() -> Self {
        Profile {
            symbol_id_map: HashMap::new(),
            symbols: Vec::new(),
            samples: Vec::new(),
        }
    }

    pub fn add_sample(
        &mut self,
        pid: Pid,
        comm: String,
        stack: Vec<(String, String, Option<u32>)>,
    ) {
        let mut sample = Sample {
            stack: Vec::new(),
            comm,
            pid,
        };

        for (method, path, lineno) in stack {
            sample.stack.push(Frame {
                method_idx: self.index_for(method),
                file_idx: self.index_for(path),
                lineno,
            });
        }
        self.samples.push(sample);
    }

    fn index_for(&mut self, name: String) -> usize {
        match self.symbol_id_map.get(&name) {
            Some(index) => *index as usize,
            None => {
                let idx = self.symbol_id_map.len();
                self.symbol_id_map
                    .insert(name.clone(), idx.try_into().unwrap());
                self.symbols.push(name);
                idx
            }
        }
    }

    pub fn folded(&self) -> String {
        let mut sample_count = HashMap::new();
        for sample in &self.samples {
            let mut stack = Vec::new();
            for frame in sample.stack.iter().rev() {
                let method_name = &self.symbols[frame.method_idx];
                let path = &self.symbols[frame.file_idx];
                let lineno = frame.lineno;

                match lineno {
                    Some(lineno) => {
                        stack.push(format!("{method_name} - {path}:{lineno}"));
                    }
                    None => {
                        stack.push(format!("{method_name} - {path}"));
                    }
                };
            }

            // https://www.reddit.com/r/rust/comments/2xjhli/best_way_to_increment_counter_in_a_map/
            match sample_count.get_mut(&stack) {
                Some(count) => *count += 1,
                None => {
                    sample_count.insert(stack.clone(), 1);
                }
            };
        }

        let mut result = String::new();
        for (stack, count) in sample_count {
            writeln!(
                result,
                "{} {}",
                stack.into_iter().collect::<Vec<_>>().join(";"),
                count
            )
            .unwrap();
        }
        result
    }
}
