use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::ffi::{CString, OsStr};
use std::fmt::Write as _;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Component, Path, PathBuf};

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

#[derive(Debug, Deserialize, Serialize)]
struct ManagedMarker {
    schema: u32,
    source: String,
    version: String,
    skill_sha256: String,
}

pub(super) fn install_target(target: &SkillTarget, force: bool) -> anyhow::Result<InstallOutcome> {
    let directory =
        open_target_directory(target, true)?.expect("create always returns a directory");
    if let Some(existing) = directory.read_optional(SKILL_FILE)? {
        if existing == EMBEDDED_SKILL.as_bytes() {
            let managed = directory
                .read_optional(MANAGED_MARKER)?
                .and_then(|raw| parse_sloosh_marker(&raw))
                .is_some_and(|marker| marker.skill_sha256 == sha256_hex(&existing));
            return Ok(if managed {
                InstallOutcome::Current
            } else {
                InstallOutcome::CurrentExternal
            });
        }
        let marker = directory.read_optional(MANAGED_MARKER)?;
        if force {
            directory.atomic_write(SKILL_FILE, EMBEDDED_SKILL.as_bytes(), true)?;
            write_marker(&directory)?;
            return Ok(InstallOutcome::Updated);
        }
        let Some(marker) = marker else {
            return Ok(InstallOutcome::PreservedExternal);
        };
        let Some(marker) = parse_sloosh_marker(&marker) else {
            return Ok(InstallOutcome::PreservedExternal);
        };
        if marker.skill_sha256 == sha256_hex(&existing) {
            directory.atomic_write(SKILL_FILE, EMBEDDED_SKILL.as_bytes(), true)?;
            write_marker(&directory)?;
            return Ok(InstallOutcome::Updated);
        }
        return Ok(InstallOutcome::PreservedModified);
    }
    directory.atomic_write(SKILL_FILE, EMBEDDED_SKILL.as_bytes(), false)?;
    write_marker(&directory)?;
    Ok(InstallOutcome::Installed)
}

pub(super) fn inspect_target(target: &SkillTarget) -> anyhow::Result<SkillStatus> {
    let Some(directory) = open_target_directory(target, false)? else {
        return Ok(SkillStatus::Missing);
    };
    let Some(skill) = directory.read_optional(SKILL_FILE)? else {
        return Ok(SkillStatus::Missing);
    };
    let marker = directory
        .read_optional(MANAGED_MARKER)?
        .and_then(|raw| parse_sloosh_marker(&raw));
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

fn parse_sloosh_marker(raw: &[u8]) -> Option<ManagedMarker> {
    let marker = serde_json::from_slice::<ManagedMarker>(raw).ok()?;
    (marker.schema == 1 && marker.source == "sloosh").then_some(marker)
}

#[cfg(test)]
fn skill_path(target: &SkillTarget) -> PathBuf {
    target.directory.join("SKILL.md")
}

#[cfg(test)]
fn marker_path(target: &SkillTarget) -> PathBuf {
    target.directory.join(MANAGED_MARKER)
}

fn write_marker(directory: &SkillDirectory) -> anyhow::Result<()> {
    let replace = directory.read_optional(MANAGED_MARKER)?.is_some();
    let marker = ManagedMarker {
        schema: 1,
        source: "sloosh".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        skill_sha256: sha256_hex(EMBEDDED_SKILL.as_bytes()),
    };
    let mut encoded = serde_json::to_vec_pretty(&marker)?;
    encoded.push(b'\n');
    directory.atomic_write(MANAGED_MARKER, &encoded, replace)
}

fn sha256_hex(contents: &[u8]) -> String {
    let digest = Sha256::digest(contents);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

struct SkillDirectory {
    file: File,
    display: PathBuf,
}

fn open_target_directory(
    target: &SkillTarget,
    create: bool,
) -> anyhow::Result<Option<SkillDirectory>> {
    let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&target.root)
        .with_context(|| format!("could not open skill root {}", target.root.display()))?;
    validate_owned_directory(&root.metadata()?, &target.root)?;

    let relative = target
        .directory
        .strip_prefix(&target.root)
        .with_context(|| {
            format!(
                "skill directory {} is outside its root {}",
                target.directory.display(),
                target.root.display()
            )
        })?;
    let mut current = SkillDirectory {
        file: root,
        display: target.root.clone(),
    };
    for component in relative.components() {
        let Component::Normal(name) = component else {
            anyhow::bail!("skill directory contains an unsafe path component");
        };
        let next_display = current.display.join(name);
        let name = c_string(name)?;
        let mut opened = open_directory_at(&current.file, &name);
        if opened
            .as_ref()
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            if !create {
                return Ok(None);
            }
            let rc = unsafe { libc::mkdirat(current.file.as_raw_fd(), name.as_ptr(), 0o755) };
            if rc != 0 {
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(error)
                        .with_context(|| format!("could not create {}", next_display.display()));
                }
            }
            opened = open_directory_at(&current.file, &name);
        }
        let file = opened.map_err(|error| directory_open_error(error, &next_display))?;
        validate_owned_directory(&file.metadata()?, &next_display)?;
        current = SkillDirectory {
            file,
            display: next_display,
        };
    }
    Ok(Some(current))
}

fn open_directory_at(parent: &File, name: &CString) -> std::io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a new owned descriptor and this File takes sole ownership.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn directory_open_error(error: std::io::Error, path: &Path) -> anyhow::Error {
    if matches!(error.raw_os_error(), Some(libc::ELOOP))
        || std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        anyhow::anyhow!("refusing skill directory symlink at {}", path.display())
    } else {
        anyhow::Error::new(error).context(format!("could not open {}", path.display()))
    }
}

fn validate_owned_directory(metadata: &Metadata, path: &Path) -> anyhow::Result<()> {
    if !metadata.is_dir() {
        anyhow::bail!("skill path is not a directory: {}", path.display());
    }
    let expected_uid = unsafe { libc::geteuid() };
    if metadata.uid() != expected_uid {
        anyhow::bail!(
            "refusing skill directory {} owned by uid {}; expected uid {}",
            path.display(),
            metadata.uid(),
            expected_uid
        );
    }
    if metadata.mode() & 0o022 != 0 {
        anyhow::bail!(
            "refusing group- or other-writable skill directory {} (mode {:o})",
            path.display(),
            metadata.mode() & 0o7777
        );
    }
    Ok(())
}

impl SkillDirectory {
    fn read_optional(&self, name: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let name_c = c_string(OsStr::new(name))?;
        let fd = unsafe {
            libc::openat(
                self.file.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::NotFound {
                return Ok(None);
            }
            if matches!(error.raw_os_error(), Some(libc::ELOOP)) {
                anyhow::bail!(
                    "refusing skill file symlink at {}",
                    self.display.join(name).display()
                );
            }
            return Err(error)
                .with_context(|| format!("could not open {}", self.display.join(name).display()));
        }
        // SAFETY: openat returned a new owned descriptor and this File takes sole ownership.
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        let path = self.display.join(name);
        if !metadata.is_file() {
            anyhow::bail!("skill path is not a regular file: {}", path.display());
        }
        validate_owned_file(&metadata, &path)?;
        if metadata.len() > MAX_MANAGED_FILE_BYTES {
            anyhow::bail!("skill file is too large: {}", path.display());
        }
        let mut contents = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_MANAGED_FILE_BYTES + 1)
            .read_to_end(&mut contents)
            .with_context(|| format!("could not read {}", path.display()))?;
        if contents.len() as u64 > MAX_MANAGED_FILE_BYTES {
            anyhow::bail!("skill file is too large: {}", path.display());
        }
        Ok(Some(contents))
    }

    fn atomic_write(&self, name: &str, contents: &[u8], replace: bool) -> anyhow::Result<()> {
        let destination = c_string(OsStr::new(name))?;
        let mut temp = None;
        for _ in 0..32 {
            let temp_name = format!(".sloosh-skill-{}.tmp", rand::random::<u64>());
            let temp_c = c_string(OsStr::new(&temp_name))?;
            let fd = unsafe {
                libc::openat(
                    self.file.as_raw_fd(),
                    temp_c.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o644,
                )
            };
            if fd >= 0 {
                // SAFETY: openat returned a new owned descriptor and this File takes sole ownership.
                temp = Some((temp_name, temp_c, unsafe { File::from_raw_fd(fd) }));
                break;
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::AlreadyExists {
                return Err(error).with_context(|| {
                    format!(
                        "could not create a temporary file in {}",
                        self.display.display()
                    )
                });
            }
        }
        let (temp_name, temp_c, mut file) = temp.ok_or_else(|| {
            anyhow::anyhow!(
                "could not allocate a temporary skill file in {}",
                self.display.display()
            )
        })?;

        let result = (|| -> anyhow::Result<()> {
            file.write_all(contents).with_context(|| {
                format!(
                    "could not write {}",
                    self.display.join(&temp_name).display()
                )
            })?;
            file.sync_all().with_context(|| {
                format!("could not sync {}", self.display.join(&temp_name).display())
            })?;
            drop(file);

            let rc = unsafe {
                if replace {
                    libc::renameat(
                        self.file.as_raw_fd(),
                        temp_c.as_ptr(),
                        self.file.as_raw_fd(),
                        destination.as_ptr(),
                    )
                } else {
                    libc::linkat(
                        self.file.as_raw_fd(),
                        temp_c.as_ptr(),
                        self.file.as_raw_fd(),
                        destination.as_ptr(),
                        0,
                    )
                }
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!("could not install {}", self.display.join(name).display())
                });
            }
            if !replace {
                unlink_at(&self.file, &temp_c).with_context(|| {
                    format!(
                        "could not remove {}",
                        self.display.join(&temp_name).display()
                    )
                })?;
            }
            self.file
                .sync_all()
                .with_context(|| format!("could not sync {}", self.display.display()))?;
            Ok(())
        })();
        let _ = unlink_at(&self.file, &temp_c);
        result
    }
}

fn validate_owned_file(metadata: &Metadata, path: &Path) -> anyhow::Result<()> {
    let expected_uid = unsafe { libc::geteuid() };
    if metadata.uid() != expected_uid {
        anyhow::bail!(
            "refusing skill file {} owned by uid {}; expected uid {}",
            path.display(),
            metadata.uid(),
            expected_uid
        );
    }
    if metadata.mode() & 0o022 != 0 {
        anyhow::bail!(
            "refusing group- or other-writable skill file {} (mode {:o})",
            path.display(),
            metadata.mode() & 0o7777
        );
    }
    Ok(())
}

fn unlink_at(directory: &File, name: &CString) -> std::io::Result<()> {
    let rc = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn c_string(name: &OsStr) -> anyhow::Result<CString> {
    CString::new(name.as_bytes()).context("skill path contains a NUL byte")
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestDir(PathBuf);

    impl TestDir {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sloosh-skill-{tag}-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn target(&self) -> SkillTarget {
            SkillTarget {
                agent: "test",
                root: self.0.clone(),
                directory: self.0.join("skills/sloosh"),
            }
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn fresh_target_installs_embedded_skill() {
        let temp = TestDir::new("fresh");
        let target = temp.target();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::Installed);
        assert_eq!(
            std::fs::read_to_string(skill_path(&target)).unwrap(),
            EMBEDDED_SKILL
        );
    }

    #[test]
    fn repeated_install_is_current_and_keeps_managed_marker() {
        let temp = TestDir::new("current");
        let target = temp.target();
        install_target(&target, false).unwrap();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::Current);
        assert!(target.directory.join(".sloosh-managed.json").is_file());
    }

    #[test]
    fn matching_external_skill_remains_externally_managed() {
        let temp = TestDir::new("matching-external");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::write(skill_path(&target), EMBEDDED_SKILL).unwrap();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::CurrentExternal);
        assert!(!marker_path(&target).exists());
        assert_eq!(
            inspect_target(&target).unwrap(),
            SkillStatus::CurrentExternal
        );
    }

    #[test]
    fn external_skill_is_preserved_without_force() {
        let temp = TestDir::new("external");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::write(skill_path(&target), b"external marketplace skill\n").unwrap();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::PreservedExternal);
        assert_eq!(
            std::fs::read(skill_path(&target)).unwrap(),
            b"external marketplace skill\n"
        );
        assert!(!marker_path(&target).exists());
    }

    #[test]
    fn force_replaces_external_skill_and_takes_ownership() {
        let temp = TestDir::new("force-external");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::write(skill_path(&target), b"external marketplace skill\n").unwrap();

        let outcome = install_target(&target, true).unwrap();

        assert_eq!(outcome, InstallOutcome::Updated);
        assert_eq!(
            std::fs::read_to_string(skill_path(&target)).unwrap(),
            EMBEDDED_SKILL
        );
        assert!(marker_path(&target).is_file());
    }

    #[test]
    fn managed_unchanged_skill_is_upgraded() {
        let temp = TestDir::new("managed-upgrade");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        let old_skill = b"old embedded skill\n";
        std::fs::write(skill_path(&target), old_skill).unwrap();
        let marker = ManagedMarker {
            schema: 1,
            source: "sloosh".to_string(),
            version: "0.0.9".to_string(),
            skill_sha256: sha256_hex(old_skill),
        };
        std::fs::write(
            marker_path(&target),
            serde_json::to_vec_pretty(&marker).unwrap(),
        )
        .unwrap();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::Updated);
        assert_eq!(
            std::fs::read_to_string(skill_path(&target)).unwrap(),
            EMBEDDED_SKILL
        );
    }

    #[test]
    fn modified_managed_skill_is_preserved_without_force() {
        let temp = TestDir::new("managed-modified");
        let target = temp.target();
        install_target(&target, false).unwrap();
        std::fs::write(skill_path(&target), b"user customization\n").unwrap();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::PreservedModified);
        assert_eq!(
            std::fs::read(skill_path(&target)).unwrap(),
            b"user customization\n"
        );
    }

    #[test]
    fn status_reports_missing_without_creating_directories() {
        let temp = TestDir::new("status-missing");
        let target = temp.target();

        let status = inspect_target(&target).unwrap();

        assert_eq!(status, SkillStatus::Missing);
        assert!(!target.directory.exists());
    }

    #[test]
    fn status_reports_current_managed_skill() {
        let temp = TestDir::new("status-current-managed");
        let target = temp.target();
        install_target(&target, false).unwrap();

        let status = inspect_target(&target).unwrap();

        assert_eq!(status, SkillStatus::CurrentManaged);
    }

    #[test]
    fn status_reports_different_unmanaged_skill_as_external() {
        let temp = TestDir::new("status-external");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::write(skill_path(&target), b"marketplace version\n").unwrap();

        let status = inspect_target(&target).unwrap();

        assert_eq!(status, SkillStatus::External);
    }

    #[test]
    fn auto_target_defaults_to_portable_codex_path() {
        let temp = TestDir::new("auto-default");

        let targets = resolve_targets_from_home(&temp.0, SkillAgent::Auto).unwrap();

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].agent, "Codex");
        assert_eq!(targets[0].directory, temp.0.join(".agents/skills/sloosh"));
    }

    #[test]
    fn malformed_marker_preserves_existing_skill() {
        let temp = TestDir::new("malformed-marker");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::write(skill_path(&target), b"existing skill\n").unwrap();
        std::fs::write(marker_path(&target), b"not-json\n").unwrap();

        let outcome = install_target(&target, false).unwrap();

        assert_eq!(outcome, InstallOutcome::PreservedExternal);
        assert_eq!(
            std::fs::read(skill_path(&target)).unwrap(),
            b"existing skill\n"
        );
    }

    #[test]
    fn auto_target_selects_both_detected_agents() {
        let temp = TestDir::new("auto-detected");
        std::fs::create_dir(temp.0.join(".codex")).unwrap();
        std::fs::create_dir(temp.0.join(".claude")).unwrap();

        let targets = resolve_targets_from_home(&temp.0, SkillAgent::Auto).unwrap();

        assert_eq!(
            targets
                .iter()
                .map(|target| target.agent)
                .collect::<Vec<_>>(),
            vec!["Codex", "Claude Code"]
        );
    }

    #[test]
    fn status_distinguishes_upgrade_from_user_modification() {
        let temp = TestDir::new("status-managed-drift");
        let target = temp.target();
        install_target(&target, false).unwrap();
        let marker: ManagedMarker =
            serde_json::from_slice(&std::fs::read(marker_path(&target)).unwrap()).unwrap();

        let older = b"older managed skill\n";
        std::fs::write(skill_path(&target), older).unwrap();
        let older_marker = ManagedMarker {
            skill_sha256: sha256_hex(older),
            ..marker
        };
        std::fs::write(
            marker_path(&target),
            serde_json::to_vec_pretty(&older_marker).unwrap(),
        )
        .unwrap();
        assert_eq!(
            inspect_target(&target).unwrap(),
            SkillStatus::UpgradeAvailable
        );

        std::fs::write(skill_path(&target), b"user edited skill\n").unwrap();
        assert_eq!(inspect_target(&target).unwrap(), SkillStatus::Modified);
    }

    #[cfg(unix)]
    #[test]
    fn skill_directory_symlink_is_refused() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("directory-symlink");
        let target = temp.target();
        let outside = temp.0.join("outside");
        std::fs::create_dir_all(target.directory.parent().unwrap()).unwrap();
        std::fs::create_dir(&outside).unwrap();
        symlink(&outside, &target.directory).unwrap();

        let error = install_target(&target, false).unwrap_err().to_string();

        assert!(error.contains("symlink"), "{error}");
        assert!(!outside.join("SKILL.md").exists());
    }

    #[test]
    fn group_writable_skill_directory_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = TestDir::new("writable-directory");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::set_permissions(&target.directory, std::fs::Permissions::from_mode(0o777))
            .unwrap();

        let error = install_target(&target, false).unwrap_err().to_string();

        assert!(error.contains("group- or other-writable"), "{error}");
        assert!(!skill_path(&target).exists());
    }

    #[test]
    fn skill_file_symlink_is_refused() {
        use std::os::unix::fs::symlink;

        let temp = TestDir::new("file-symlink");
        let target = temp.target();
        let outside = temp.0.join("outside-skill");
        std::fs::create_dir_all(&target.directory).unwrap();
        std::fs::write(&outside, b"outside\n").unwrap();
        symlink(&outside, skill_path(&target)).unwrap();

        let error = install_target(&target, true).unwrap_err().to_string();

        assert!(error.contains("symlink"), "{error}");
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside\n");
    }

    #[test]
    fn oversized_skill_is_refused_without_replacement() {
        let temp = TestDir::new("oversized-file");
        let target = temp.target();
        std::fs::create_dir_all(&target.directory).unwrap();
        let oversized = vec![b'x'; MAX_MANAGED_FILE_BYTES as usize + 1];
        std::fs::write(skill_path(&target), &oversized).unwrap();

        let error = install_target(&target, true).unwrap_err().to_string();

        assert!(error.contains("too large"), "{error}");
        assert_eq!(std::fs::read(skill_path(&target)).unwrap(), oversized);
    }
}
