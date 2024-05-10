use clap;
use clap::Parser;
use std::collections::HashMap;
use std::{env, io};
use std::io::BufRead;
use std::os::unix::process::ExitStatusExt;
//use std::process::Command;
use futures::future::join_all;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use vaultrs::kv2;

use std::process::{ExitCode, ExitStatus, Stdio, Termination};
use regex::Regex;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(name = "myapp")]
struct Args {
    command: String,
    #[arg(num_args(0..))]
    cmd: Vec<String>,
}

#[derive(Debug)]
struct ReturnVal {
    code: ExitStatus,
}

impl ReturnVal {
    fn new(code: ExitStatus) -> ReturnVal {
        ReturnVal { code }
    }
}

impl Termination for ReturnVal {
    fn report(self) -> ExitCode {
        let c: u8 = self.code.code().unwrap_or(1) as u8;
        ExitCode::from(c)
    }
}

async fn find_secret(key: &str, val: &str) -> (String, String) {
    // TODO: Nice error if token or addr is not present
    let client = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(env::var("VAULT_ADDR").unwrap())
            .token(env::var("VAULT_TOKEN").unwrap())
            .build()
            .unwrap(),
    )
    .unwrap();

    if val.starts_with("vault://") {
        let new_val = val.replace("vault://", "");
        let parts = new_val.split("/").collect::<Vec<_>>();

        assert!(
            parts.len() >= 4,
            "Invalid vault secret, should be of format 'vault://v2/secret/group/key'"
        );

        match parts[0] {
            "v1" => todo!("Implement access to v1 secrets"),
            "v2" => {
                let val: HashMap<String, String> =
                    kv2::read(&client, parts[1], parts[2]).await.unwrap();

                let ret = &val[parts[3]];
                (String::from(key), String::from(ret))
            }
            _ => panic!("Unknown vault secret version"),
        }
    } else {
        (String::from(key), String::from(val))
    }
}

async fn interpolate_env() -> Vec<(String, String)> {
    let env = env::vars().collect::<Vec<_>>();
    let env_promises: Vec<_> = env
        .iter()
        .map(|(key, val)| async { find_secret(key, val).await })
        .collect();

    let env: Vec<(String, String)> = join_all(env_promises).await;
    env
}

async fn spawn_and_print(args: Vec<String>) -> Result<ExitStatus, Box<dyn std::error::Error>> {
    let cmd = args[0].to_owned();
    let mut command = Command::new(&cmd);
    command.args(&args[1..]);

    let env = interpolate_env().await;
    command.envs(env);
    command.stdout(Stdio::piped());

    let child_start = command.spawn();
    if child_start.is_err() {
        let err = child_start.err().unwrap();
        panic!("Failed to spawn child process {} {}", cmd, err);
    }
    let mut child = child_start.unwrap();
    // TODO: pipe stderr too
    let stdout = child
        .stdout
        .take()
        .expect("child did not have a handle to stdout");

    let mut reader = BufReader::new(stdout).lines();

    let child_1 = tokio::spawn(async move {
        let status = child
            .wait()
            .await
            .expect("child process encountered an error");

        return status;
    });

    while let Some(line) = reader.next_line().await? {
        println!("{}", line);
    }

    let exit_code = child_1.await;
    return Ok(exit_code?);
}

#[tokio::main]
async fn main() -> Result<ReturnVal, Box<dyn std::error::Error>> {
    let args = Args::parse();

    let res = match args.command.as_str() {
        "run" => {
            let all_args: Vec<_> = env::args().collect();
            let command_start_index = all_args.iter().position(|r| r == "--");
            match command_start_index {
                Some(index) => {
                    let exit_code = spawn_and_print(all_args[index + 1..].to_vec()).await?;
                    Ok(ReturnVal::new(exit_code))
                }
                None => panic!("No shell command to run"),
            }
        }
        "inject" => {
            for line in io::stdin().lock().lines() {
                let line = line.unwrap();
                let re = Regex::new(r#"vault://[\w/]+"#).unwrap();
                if let Some(vault_path) = re.captures(&line) {
                    let vault_path= vault_path.get(0).unwrap().as_str();
                    println!("Found path: {}", vault_path);
                    let (_key,val) = find_secret(&"key", vault_path).await;
                    println!("{}", line.replace(vault_path,val.as_str()))
                } else {
                    println!("{}",line);

                }
            }
            Ok(ReturnVal::new(ExitStatus::from_raw(0)))
        }
        &_ => todo!(),
    };

    return res;
}
