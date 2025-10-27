use crate::cli::ParseCommand;
use anyhow::Result;
use colored::*;
use crate::parser;

pub fn execute_parse(cmd: ParseCommand) -> Result<()> {
    let ParseCommand {
        file_path,
        event_id,
        search,
        detect,
        output,
        after,
        before,
    } = cmd;
    println!("{}", "Security Log Analyzer".bright_cyan().bold());
    println!("Analyzing file: {}\n", file_path.to_string_lossy().bright_yellow());
    let events = parser::parse_evtx_file(&file_path)?;
    dbg!(events);
    Ok(())
}