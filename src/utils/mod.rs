// Copyright 2025 Magic Mount-rs Authors
// SPDX-License-Identifier: GPL-3.0-or-later

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod ksucalls;

use std::{
    fs::{self, create_dir_all},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result, anyhow, bail};
#[cfg(any(target_os = "linux", target_os = "android"))]
use extattr::{Flags as XattrFlags, lgetxattr, lsetxattr};
use regex_lite::Regex;

use crate::defs;
#[cfg(any(target_os = "linux", target_os = "android"))]
use crate::defs::SELINUX_XATTR;

/// Validate `module_id` format and security
/// Module ID must match: ^[a-zA-Z][a-zA-Z0-9._-]+$
/// - Must start with a letter (a-zA-Z)
/// - Followed by one or more alphanumeric, dot, underscore, or hyphen characters
/// - Minimum length: 2 characters
pub fn validate_module_id(module_id: &str) -> Result<()> {
    let re = Regex::new(r"^[a-zA-Z][a-zA-Z0-9._-]+$")?;
    if re.is_match(module_id) {
        Ok(())
    } else {
        Err(anyhow!(
            "Invalid module ID: '{module_id}'. Must match /^[a-zA-Z][a-zA-Z0-9._-]+$/"
        ))
    }
}

pub fn generate_tmp() -> PathBuf {
    let mut name = String::new();

    for _ in 0..10 {
        name.push(fastrand::alphanumeric());
    }

    Path::new("/mnt").join(name)
}

pub fn lsetfilecon<P: AsRef<Path>>(path: P, con: &str) -> Result<()> {
    log::debug!("file: {},con: {}", path.as_ref().display(), con);
    lsetxattr(&path, SELINUX_XATTR, con, XattrFlags::empty()).with_context(|| {
        format!(
            "Failed to change SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn lgetfilecon<P>(path: P) -> Result<String>
where
    P: AsRef<Path>,
{
    let con = lgetxattr(&path, SELINUX_XATTR).with_context(|| {
        format!(
            "Failed to get SELinux context for {}",
            path.as_ref().display()
        )
    })?;
    let con = String::from_utf8_lossy(&con);
    Ok(con.to_string())
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn lgetfilecon<P>(path: P) -> Result<String>
where
    P: AsRef<Path>,
{
    unimplemented!()
}

pub fn ensure_dir_exists<P>(dir: P) -> Result<()>
where
    P: AsRef<Path>,
{
    let result = create_dir_all(&dir);
    if dir.as_ref().is_dir() && result.is_ok() {
        Ok(())
    } else {
        bail!("{} is not a regular directory", dir.as_ref().display())
    }
}

pub fn update_desc(files: u32, symbols: u32) {
    let text = format!("😋 mounted files: {files}, mounted symbols: {symbols}");

    if ksucalls::KSU.load(std::sync::atomic::Ordering::Relaxed) {
        let result = Command::new("ksud")
            .arg("module")
            .arg("config")
            .arg("set")
            .arg("override.description")
            .arg(&text)
            .output();

        if let Ok(ret) = result
            && ret.status.success()
        {
            return;
        }
    }

    if let Ok(mut f) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .truncate(true)
        .open(defs::MODULE_PROP)
    {
        let buf = BufReader::new(&f);
        let new: Vec<String> = buf
            .lines()
            .map_while(Result::ok)
            .map(|l| {
                if l.starts_with("description") {
                    format!("description={text}")
                } else {
                    l
                }
            })
            .collect();

        f.write_all(new.join("\n").as_bytes())
            .map_err(|e| log::error!("Failed to update description: {e}"))
            .unwrap();
    }
}
