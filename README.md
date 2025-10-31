# Security Log Analyzer

A Windows Sysmon log analysis tool developed to help security professionals and system administrators analyze and
monitor system events. This tool provides both offline log parsing capabilities and real-time monitoring of Sysmon
events.

## Project Origin

This project was developed as a capstone project for the Rust Bootcamp Summer 2025.

## Features

- Parse Sysmon .evtx log files
- Real-time monitoring of Sysmon events (Windows only)
- Event filtering by ID, time range, and search terms
- Anomaly detection capabilities
- Structured output formatting

## Installation

To install and run the project, ensure you have Rust and Cargo installed. Then execute:
```shell
cargo build --release
```
To parse an existing Sysmon `.evtx` file:

```shell
cargo run --release -- parse <path to .evtx file>
```
Use --help to see additional options.

To monitor Sysmon events in real-time:
```shell
cargo run --release -- watch
```
Watch option is only available on Windows and needs more testing to be considered stable.
Before using the watch command, be sure to have Sysmon installed and active and run this tool with admin privileges.

## Enable Logging
This tool support structured loggin via `tracing` crate. To enable logging, set the `RUST_LOG` environment variable to
`info` or `debug`.
- Windows:
```powershell
$env:RUST_LOG="info"
cargo run --release -- parse "C:\Logs\Sysmon.evtx"
```
- Linux / MacOS:
```bash
RUST_LOG=info cargo run --release -- parse /path/to/Sysmon.evtx
```
