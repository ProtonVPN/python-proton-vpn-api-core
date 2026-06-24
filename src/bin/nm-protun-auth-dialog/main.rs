// -----------------------------------------------------------------------------
// Copyright (c) 2025 Proton AG
//
// This file is part of ProtonVPN.
//
// ProtonVPN is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// ProtonVPN is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with ProtonVPN.  If not, see <https://www.gnu.org/licenses/>.
// -----------------------------------------------------------------------------

//! NetworkManager VPN auth-dialog for protun
//!
//! This program is called by NetworkManager's secret agents (like GNOME Shell)
//! to retrieve VPN secrets from the keyring or prompt the user for them.
//!
//! Usage:
//!   protun-auth-dialog -u <uuid> -n <name> -s <service> [-i] [--external-ui-mode] [-r] [-t <hint>]
//!
//! Input (stdin):
//!   DATA_KEY=<key>
//!   DATA_VAL=<value>
//!   SECRET_KEY=<key>
//!   SECRET_VAL=<value>
//!   DONE
//!   QUIT
//!
//! Output (stdout, external-ui-mode):
//!   [VPN Plugin UI]
//!   Version=2
//!   Title=...
//!   Description=...
//!
//!   [secret-name]
//!   Value=<secret value>
//!   Label=<human readable label>
//!   IsSecret=true
//!   ShouldAsk=true/false

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use clap::Parser;

/// NetworkManager VPN auth-dialog for protun
#[derive(Parser, Debug)]
#[command(name = "protun-auth-dialog")]
#[command(about = "Retrieve VPN secrets for protun connections")]
struct Args {
    /// Connection UUID
    #[arg(short = 'u', long = "uuid")]
    uuid: String,

    /// Connection name
    #[arg(short = 'n', long = "name")]
    name: String,

    /// VPN service type
    #[arg(short = 's', long = "service")]
    service: String,

    /// Allow user interaction
    #[arg(short = 'i', long = "allow-interaction")]
    allow_interaction: bool,

    /// Use external UI mode (output form descriptions for GNOME Shell)
    #[arg(long = "external-ui-mode")]
    external_ui_mode: bool,

    /// Reprompt for secrets (previous attempt failed)
    #[arg(short = 'r', long = "reprompt")]
    reprompt: bool,

    /// Hints about which secrets are needed
    #[arg(short = 't', long = "hint")]
    hints: Vec<String>,
}

/// Secret key name for the WireGuard private key
const SECRET_PRIVATE_KEY: &str = "private-key";
const SECRET_PRIVATE_KEY_FLAGS: &str = "private-key-flags";
const NM_SETTING_SECRET_FLAG_NOT_REQUIRED: u32 = 0x04;
const SERVICE_NAMESPACE: &str = "org.freedesktop.NetworkManager.protun";

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    RuntimeError(String),
}

/// Iterate over key-value entries from stdin until "DONE" is encountered.
/// Each entry is either a regular data entry (DATA_KEY/DATA_VAL) or a secret entry (SECRET_KEY/SECRET_VAL).
/// Returns an iterator of (key, value, is_secret) tuples.
///
/// Example input:
/// DATA_KEY=setting1
/// DATA_VAL=value1
/// SECRET_KEY=private-key
/// SECRET_VAL=secretvalue
/// DONE
fn iter_entries<B: BufRead>(buf: B) -> impl Iterator<Item = io::Result<(String, String, bool)>> {
    let mut lines = buf.lines();
    let mut current_key: Option<String> = None;
    let mut is_secret = false;

    let iterate_entries = move || -> Option<io::Result<(String, String, bool)>> {
        while let Some(Ok(line)) = lines.next() {
            if line == "DONE" {
                return None;
            }

            if let Some(val) = line.strip_prefix("DATA_KEY=") {
                current_key = Some(val.to_string());
                is_secret = false;
            } else if let Some(val) = line.strip_prefix("DATA_VAL=") {
                if let Some(key) = current_key.take() {
                    return Some(Ok((key, val.to_string(), false)));
                }
            } else if let Some(val) = line.strip_prefix("SECRET_KEY=") {
                current_key = Some(val.to_string());
                is_secret = true;
            } else if let Some(val) = line.strip_prefix("SECRET_VAL=") {
                if let Some(key) = current_key.take() {
                    if is_secret {
                        return Some(Ok((key, val.to_string(), true)));
                    }
                }
            }
        }

        None
    };

    std::iter::from_fn(iterate_entries)
}

trait KeyringLookup {
    async fn lookup(&self, uuid: &str, secret_name: &str) -> Option<String>;
}

struct oo7Keyring;

impl KeyringLookup for oo7Keyring {
    async fn lookup(&self, uuid: &str, secret_name: &str) -> Option<String> {
        // Placeholder implementation - replace with actual oo7 keyring lookup
           let keyring = oo7::Keyring::new().await.ok()?;

        let attrs = std::collections::HashMap::from([
            ("connection-uuid", uuid),
            ("setting-name", "vpn"),
            ("setting-key", secret_name),
        ]);

        let items = keyring.search_items(&attrs).await.ok()?;
        let item = items.into_iter().next()?;

        let secret = item.secret().await.ok()?;
        let s = std::str::from_utf8(secret.as_bytes()).ok()?;
        let trimmed = s.trim_end();

        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }
}

/// Output the result in external-ui-mode format
fn output_external_ui<O>(
    mut output: O,
    vpn_name: &str,
    private_key: &str,
)
where
    O: Write,
{
    writeln!(output, "[VPN Plugin UI]").ok();
    writeln!(output, "Version=2").ok();
    writeln!(output, "Title=VPN Authentication Required").ok();
    writeln!(
        output,
        "Description=Credentials are required to connect to the VPN \"{}\".",
        vpn_name
    )
    .ok();
    writeln!(output).ok();

    writeln!(output, "[{}]", SECRET_PRIVATE_KEY).ok();
    writeln!(output, "Value={}", private_key).ok();
    writeln!(output, "Label={}", "WireGuard Private Key").ok();
    writeln!(output, "IsSecret={}", true).ok();
    writeln!(output, "ShouldAsk={}", false).ok();
    writeln!(output).ok();
}

/// Output secrets in standard mode (non-external-ui)
fn output_standard<O>(mut output: O, private_key: &str)
where
    O: Write,
{
    writeln!(output, "{}", SECRET_PRIVATE_KEY).ok();
    writeln!(output, "{}", private_key).ok();

    writeln!(output).ok();
    writeln!(output).ok();

    output.flush().ok();
}

async fn run_auth_dialog<I, O, L>(args: Args, mut input : I, mut output : O, keyring: L) -> Result<(), Error>
where
    I: BufRead,
    O: Write,
    L: KeyringLookup,
{
    // Validate service type
    if args.service != SERVICE_NAMESPACE {
        return Err(Error::RuntimeError(format!("This auth-dialog only works with '{}' service", SERVICE_NAMESPACE)));
    }

    // Read existing VPN data and secrets from stdin
    let mut existing_private_key: Option<String> = None;
    let mut need_private_key : bool = true;

    for entry in iter_entries(input) {
        let (key, value, is_secret) = entry?;
        if is_secret && key == SECRET_PRIVATE_KEY {
            existing_private_key = Some(value);
        } else if key == SECRET_PRIVATE_KEY_FLAGS {
            let flags = value.parse::<u32>().unwrap_or(0);
            need_private_key = (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED) == 0;
        }
    }

    // Exit early if no secrets are needed
    if !need_private_key {
        if args.external_ui_mode {
            writeln!(output, "[VPN Plugin UI]").ok();
            writeln!(output, "Version=2").ok();
            writeln!(output, "Title=No Authentication Required").ok();
            writeln!(output, "Description=No secrets are required for this connection.").ok();
            writeln!(output).ok();
        } else {
            // Output empty response for standard mode
            writeln!(output).ok();
            writeln!(output).ok();
        }
        return Ok(());
    }

    if existing_private_key.is_none() {
        existing_private_key = keyring.lookup(&args.uuid, SECRET_PRIVATE_KEY).await;
    }

    if let Some(key) = &existing_private_key {
        if args.external_ui_mode { output_external_ui(output, &args.name, key) } else { output_standard(output, key)}
    } else {
        return Err(Error::RuntimeError("Unable to obtain the private key and interaction is not supported".to_string()).into());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockKeyring {
        secret: Option<String>,
    }

    impl KeyringLookup for MockKeyring {
        async fn lookup(&self, _uuid: &str, _secret_name: &str) -> Option<String> {
            self.secret.clone()
        }
    }

    fn default_args() -> Args {
        Args {
            uuid: "test-uuid".to_string(),
            name: "Test VPN".to_string(),
            service: SERVICE_NAMESPACE.to_string(),
            allow_interaction: false,
            external_ui_mode: false,
            reprompt: false,
            hints: vec![],
        }
    }

    async fn run_dialog(args: Args, input: &str, keyring: MockKeyring) -> String {
        let mut output = Vec::new();
        run_auth_dialog(args, Cursor::new(input), &mut output, keyring)
            .await
            .unwrap();
        String::from_utf8(output).unwrap()
    }

    #[tokio::test]
    async fn test_stdin_key_with_standard_output() {
        let output = run_dialog(
            default_args(),
            "SECRET_KEY=private-key\n\
             SECRET_VAL=eHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=\n\
             DONE\n",
            MockKeyring { secret: None },
        )
        .await;

        assert_eq!(output, "private-key\neHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=\n\n\n");
    }

    #[tokio::test]
    async fn test_keyring_with_standard_output_output() {
        let output = run_dialog(
            default_args(),
            "DONE\n",
            MockKeyring { secret: Some("eHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=".to_string()) },
        )
        .await;

        assert_eq!(output, "private-key\neHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=\n\n\n");
    }

    #[tokio::test]
    async fn test_stdin_key_with_external_ui_output() {
        let output = run_dialog(
            Args { external_ui_mode: true, ..default_args() },
            "SECRET_KEY=private-key\n\
             SECRET_VAL=eHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=\n\
             DONE\n",
            MockKeyring { secret: None },
        )
        .await;

        assert_eq!(
            output,
            "[VPN Plugin UI]\n\
             Version=2\n\
             Title=VPN Authentication Required\n\
             Description=Credentials are required to connect to the VPN \"Test VPN\".\n\
             \n\
             [private-key]\n\
             Value=eHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=\n\
             Label=WireGuard Private Key\n\
             IsSecret=true\n\
             ShouldAsk=false\n\
             \n"
        );
    }

    #[tokio::test]
    async fn test_keyring_with_external_ui_output() {
        let output = run_dialog(
            Args { external_ui_mode: true, ..default_args() },
            "DONE\n",
            MockKeyring { secret: Some("eHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=".to_string()) },
        )
        .await;

        assert_eq!(
            output,
            "[VPN Plugin UI]\n\
             Version=2\n\
             Title=VPN Authentication Required\n\
             Description=Credentials are required to connect to the VPN \"Test VPN\".\n\
             \n\
             [private-key]\n\
             Value=eHAm8BNb+QTwU5i4lUb7gHVK3vVt8e2G9fCXaDoOlGo=\n\
             Label=WireGuard Private Key\n\
             IsSecret=true\n\
             ShouldAsk=false\n\
             \n"
        );
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    run_auth_dialog(Args::parse(), io::stdin().lock(), io::stdout(), oo7Keyring).await?;

    Ok(())
}
