//! Example: Download a compressed log file from a cluster host.
//!
//! # Prerequisites
//!
//! A valid Atlas CLI config at the default config path with credentials stored
//! in the OS keychain or the legacy config file. The easiest way is to run
//! `atlas auth login` with the official CLI first.
//!
//! # Usage
//!
//! ```sh
//! cargo run --example download_cluster_log -- \
//!   --host-name <HOST> \
//!   --log-name mongodb \
//!   --output cluster.log.gz
//! ```
//!
//! The group (project) ID is read from the active Atlas CLI profile when
//! `--group-id` is omitted.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};

use mongodb_atlas_cli::atlas::{client::AtlasClient, operation};

// https://www.mongodb.com/docs/api/doc/atlas-admin-api-v2/operation/operation-downloadgroupclusterlog
#[derive(Debug)]
#[operation(method = GET, version = "2023-02-01")]
#[url("/api/atlas/v2/groups/{group_id}/clusters/{host_name}/logs/{log_name}.gz")]
#[response(gzip)]
struct DownloadGroupClusterLogRequest {}

#[derive(Debug, Clone, ValueEnum)]
enum LogName {
    Mongodb,
    Mongos,
    #[value(name = "mongodb-audit-log")]
    MongodbAuditLog,
    #[value(name = "mongos-audit-log")]
    MongosAuditLog,
}

impl std::fmt::Display for LogName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogName::Mongodb => write!(f, "mongodb"),
            LogName::Mongos => write!(f, "mongos"),
            LogName::MongodbAuditLog => write!(f, "mongodb-audit-log"),
            LogName::MongosAuditLog => write!(f, "mongos-audit-log"),
        }
    }
}

#[derive(Parser, Debug)]
#[command(about = "Download a compressed log file from an Atlas cluster host")]
struct Args {
    /// Atlas project (group) ID. Defaults to the project_id in the active profile.
    #[arg(long)]
    group_id: Option<String>,

    /// Hostname of the cluster node whose logs to download.
    #[arg(long)]
    host_name: String,

    /// Which log file to download.
    #[arg(long, value_enum, default_value = "mongodb")]
    log_name: LogName,

    /// Path to write the downloaded .gz file.
    #[arg(long, default_value = "cluster.log.gz")]
    output: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let client = AtlasClient::from_defaults().context("failed to create Atlas client")?;

    let group_id = args
        .group_id
        .or_else(|| client.config().project_id.clone())
        .context("no group_id: pass --group-id or set project_id in the active profile")?;

    let op = DownloadGroupClusterLogOperation::builder()
        .url_parameters(
            DownloadGroupClusterLogOperationUrlParams::builder()
                .group_id(group_id)
                .host_name(args.host_name.clone())
                .log_name(args.log_name.to_string())
                .build(),
        )
        .build();

    println!(
        "Downloading {} logs for host {} …",
        args.log_name, args.host_name
    );

    let bytes = client.execute(op).await.context("request failed")?;

    std::fs::write(&args.output, &bytes)
        .with_context(|| format!("failed to write {}", args.output.display()))?;

    println!("Saved {} bytes to {}", bytes.len(), args.output.display());

    Ok(())
}
