use async_trait::async_trait;
use log::info;

use crate::output::{EventResult, Sink, SinkError};

pub struct TermLogger {}

#[async_trait]
impl Sink for TermLogger {
    async fn write(&mut self, result: &EventResult) -> Result<(), SinkError> {
        println!("Result registered {result}");
        Ok(())       
    }
}
