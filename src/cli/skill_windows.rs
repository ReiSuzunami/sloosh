//! Windows Agent Skill installation using reparse-point refusal and
//! same-directory atomic replacement.

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::os::windows::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};
use windows::Win32::Storage::FileSystem::{
    MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW,
};

use super::args::SkillAgent;

pub(super) const EMBEDDED_SKILL: &str = include_str!("../../skills/sloosh/SKILL.md");

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SkillTarget {
    pub agent: &'static str,
    pub root: PathBuf,
    pub directory: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InstallOutcome {
    Installed,
    Current,
    CurrentExternal,
    Updated,
    PreservedExternal,
    PreservedModified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SkillStatus {
    Missing,
    CurrentManaged,
    CurrentExternal,
    UpgradeAvailable,
    Modified,
    External,
}

const MANAGED_MARKER: &str = ".sloosh-managed.json";
const SKILL_FILE: &str = "SKILL.md";
const MAX_MANAGED_FILE_BYTES: u64 = 1024 * 1024;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[derive(Debug, Deserialize, Serialize)]
struct ManagedMarker {
    schema: u32,
    source: String,
    version: String,
    skill_sha256: String,
}

pub(super) fn install_target(target: &SkillTarget, force: bool) -> anyhow::Result<InstallOutcome> {
    let directory = open_target_directory(target, true)?.expect("create returns a directory");
    if let Some(existing) = read_optional(&directory, SKILL_FILE)? {
        if existing == EMBEDDED_SKILL.as_bytes() {
            let managed = read_optional(&directory, MANAGED_MARKER)?
                .and_then(|raw| parse_sloosh_marker(&raw))
                .is_some_and(|marker| marker.skill_sha256 == sha256_hex(&existing));
            return Ok(if managed {
                InstallOutcome::Current
            } else {
                InstallOutcome::CurrentExternal
            });
        }
        let marker = read_optional(&directory, MANAGED_MARKER)?;
        if force {
            atomic_write(&directory, SKILL_FILE, EMBEDDED_SKILL.as_bytes(), true)?;
            write_marker(&directory)?;
            return Ok(InstallOutcome::Updated);
        }
        let Some(marker) = marker.and_then(|raw| parse_sloosh_marker(&raw)) else {
            return Ok(InstallOutcome::PreservedExternal);
        };
        if marker.skill_sha256 == sha256_hex(&existing) {
            atomic_write(&directory, SKILL_FILE, EMBEDDED_SKILL.as_bytes(), true)?;
            write_marker(&directory)?;
            return Ok(InstallOutcome::Updated);
        }
        return Ok(InstallOutcome::PreservedModified);
    }
    atomic_write(&directory, SKILL_FILE, EMBEDDED_SKILL.as_bytes(), false)?;
    write_marker(&directory)?;
    Ok(InstallOutcome::Installed)
}

pub(super) fn inspect_target(target: &SkillTarget) -> anyhow::Result<SkillStatus> {
    let Some(directory) = open_target_directory(target, false)? else {
        return Ok(SkillStatus::Missing);
    };
    let Some(skill) = read_optional(&directory, SKILL_FILE)? else {
        return Ok(SkillStatus::Missing);
    };
    let marker =
        read_optional(&directory, MANAGED_MARKER)?.and_then(|raw| parse_sloosh_marker(&raw));
    if skill == EMBEDDED_SKILL.as_bytes() {
        if marker.is_some_and(|marker| marker.skill_sha256 == sha256_hex(&skill)) {
            Ok(SkillStatus::CurrentManaged)
        } else {
            Ok(SkillStatus::CurrentExternal)
        }
    } else {
        match marker {
            Some(marker) if marker.skill_sha256 == sha256_hex(&skill) => {
                Ok(SkillStatus::UpgradeAvailable)
            }
            Some(_) => Ok(SkillStatus::Modified),
            None => Ok(SkillStatus::External),
        }
    }
}

pub(super) fn resolve_targets_from_home(
    home: &Path,
    agent: SkillAgent,
) -> anyhow::Result<Vec<SkillTarget>> {
    let codex = || SkillTarget {
        agent: "Codex",
        root: home.to_path_buf(),
        directory: home.join(".agents/skills/sloosh"),
    };
    let claude = || SkillTarget {
        agent: "Claude Code",
        root: home.to_path_buf(),
        directory: home.join(".claude/skills/sloosh"),
    };
    Ok(match agent {
        SkillAgent::Codex => vec![codex()],
        SkillAgent::Claude => vec![claude()],
        SkillAgent::All => vec![codex(), claude()],
        SkillAgent::Auto => {
            let mut targets = Vec::new();
            if home.join(".agents").is_dir() || home.join(".codex").is_dir() {
                targets.push(codex());
            }
            if home.join(".claude").is_dir() {
                targets.push(claude());
            }
            if targets.is_empty() {
                targets.push(codex());
            }
            targets
        }
    })
}

fn open_target_directory(target: &SkillTarget, create: bool) -> anyhow::Result<Option<PathBuf>> {
    let relative = target
        .directory
        .strip_prefix(&target.root)
        .with_context(|| {
            format!(
                "skill target {} is outside {}",
                target.directory.display(),
                target.root.display()
            )
        })?;
    let mut current = target.root.clone();
    validate_directory(&current)?;
    for component in relative.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("skill path contains an unsafe component");
        };
        current.push(name);
        match std::fs::symlink_metadata(&current) {
            Ok(_) => validate_directory(&current)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                std::fs::create_dir(&current)
                    .with_context(|| format!("failed to create {}", current.display()))?;
                validate_directory(&current)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to inspect {}", current.display()));
            }
        }
    }
    Ok(Some(current))
}

fn validate_directory(path: &Path) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        anyhow::bail!(
            "refusing unsafe or reparse-point skill directory {}",
            path.display()
        );
    }
    Ok(())
}

fn read_optional(directory: &Path, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
    let path = directory.join(name);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()));
        }
    };
    if !metadata.is_file()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || metadata.len() > MAX_MANAGED_FILE_BYTES
    {
        anyhow::bail!("refusing unsafe managed Skill file {}", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::fs::File::open(&path)?
        .take(MAX_MANAGED_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_MANAGED_FILE_BYTES {
        anyhow::bail!("managed Skill file {} exceeds 1 MiB", path.display());
    }
    Ok(Some(bytes))
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8], replace: bool) -> anyhow::Result<()> {
    let destination = directory.join(name);
    if let Ok(metadata) = std::fs::symlink_metadata(&destination) {
        if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            anyhow::bail!(
                "refusing unsafe Skill destination {}",
                destination.display()
            );
        }
    }
    let mut random = [0_u8; 8];
    rand::fill(&mut random);
    let temporary = directory.join(format!(
        ".sloosh-tmp-{}-{}",
        std::process::id(),
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ));
    let result = (|| -> anyhow::Result<()> {
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        output.write_all(bytes)?;
        output.sync_all()?;
        drop(output);
        if replace {
            move_replace(&temporary, &destination)?;
        } else {
            std::fs::hard_link(&temporary, &destination)?;
            std::fs::remove_file(&temporary)?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

fn move_replace(source: &Path, destination: &Path) -> anyhow::Result<()> {
    let source = wide_nul(source);
    let destination = wide_nul(destination);
    // SAFETY: both paths are NUL-terminated UTF-16 buffers alive for the call.
    unsafe {
        MoveFileExW(
            windows::core::PCWSTR(source.as_ptr()),
            windows::core::PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .with_context(|| "failed to atomically replace managed Skill file")
}

fn wide_nul(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt as _;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn write_marker(directory: &Path) -> anyhow::Result<()> {
    let replace = read_optional(directory, MANAGED_MARKER)?.is_some();
    let marker = ManagedMarker {
        schema: 1,
        source: "sloosh".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        skill_sha256: sha256_hex(EMBEDDED_SKILL.as_bytes()),
    };
    let mut encoded = serde_json::to_vec_pretty(&marker)?;
    encoded.push(b'\n');
    atomic_write(directory, MANAGED_MARKER, &encoded, replace)
}

fn parse_sloosh_marker(raw: &[u8]) -> Option<ManagedMarker> {
    let marker = serde_json::from_slice::<ManagedMarker>(raw).ok()?;
    (marker.schema == 1 && marker.source == "sloosh").then_some(marker)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
    }
    output
}
