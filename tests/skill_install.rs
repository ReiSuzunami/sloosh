use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const EMBEDDED_SKILL: &str = include_str!("../skills/sloosh/SKILL.md");

struct TestHome(PathBuf);

impl TestHome {
    fn new(tag: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after Unix epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "sloosh-skill-itest-{tag}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create test HOME");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn skill_path(&self) -> PathBuf {
        self.0.join(".agents/skills/sloosh/SKILL.md")
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn sloosh(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sloosh"))
        .args(args)
        .env("HOME", home)
        .stdin(Stdio::null())
        .output()
        .expect("run sloosh")
}

#[test]
fn skill_install_and_status_work_without_a_daemon() {
    let home = TestHome::new("install");
    let output = sloosh(home.path(), &["skill", "install", "--agent", "codex"]);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(home.skill_path()).expect("installed Skill"),
        EMBEDDED_SKILL
    );
    assert!(
        home.path()
            .join(".agents/skills/sloosh/.sloosh-managed.json")
            .is_file()
    );

    let status = sloosh(home.path(), &["skill", "status", "--agent", "codex"]);
    assert!(status.status.success(), "{status:?}");
    let stdout = String::from_utf8(status.stdout).expect("UTF-8 stdout");
    assert!(
        stdout.contains("Codex: current (managed by sloosh)"),
        "{stdout}"
    );
}

#[test]
fn skill_install_preserves_external_content_until_forced() {
    let home = TestHome::new("external");
    let skill_path = home.skill_path();
    std::fs::create_dir_all(skill_path.parent().expect("skill parent"))
        .expect("create external Skill directory");
    std::fs::write(&skill_path, "external skill\n").expect("write external Skill");

    let preserved = sloosh(home.path(), &["skill", "install", "--agent", "codex"]);
    assert!(preserved.status.success(), "{preserved:?}");
    assert_eq!(
        std::fs::read_to_string(&skill_path).expect("read preserved Skill"),
        "external skill\n"
    );

    let forced = sloosh(
        home.path(),
        &["skill", "install", "--agent", "codex", "--force"],
    );
    assert!(forced.status.success(), "{forced:?}");
    assert_eq!(
        std::fs::read_to_string(&skill_path).expect("read replaced Skill"),
        EMBEDDED_SKILL
    );
}

#[test]
fn init_refuses_non_tty_before_installing_the_skill() {
    let home = TestHome::new("init-non-tty");
    let output = sloosh(home.path(), &["init", "--agent", "codex"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("human-only command"), "{stderr}");
    assert!(!home.path().join(".agents").exists());
}

#[test]
fn host_trust_refuses_non_tty_before_prompting_for_a_secret() {
    let home = TestHome::new("host-trust-non-tty");
    let output = sloosh(home.path(), &["host", "trust", "example"]);
    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8(output.stderr).expect("UTF-8 stderr");
    assert!(stderr.contains("human-only command"), "{stderr}");
    assert!(!stderr.contains("Master password"), "{stderr}");
}

#[test]
fn embedded_skill_keeps_operational_boundaries_without_duplicate_setup() {
    assert!(EMBEDDED_SKILL.contains("sloosh <command> --help"));
    assert!(EMBEDDED_SKILL.contains("sloosh approve <ID>"));
    assert!(EMBEDDED_SKILL.contains("sloosh host trust <alias>"));
    assert!(EMBEDDED_SKILL.contains("without a TTY or vault copy"));
    assert!(EMBEDDED_SKILL.contains("explicit user opt-in"));
    assert!(EMBEDDED_SKILL.contains("do not run the command again"));
}

#[test]
fn auto_install_updates_a_shared_skill_without_replacing_its_link() {
    let home = TestHome::new("shared-auto");
    assert!(
        sloosh(home.path(), &["skill", "install", "--agent", "codex"])
            .status
            .success()
    );
    let claude = home.path().join(".claude/skills/sloosh");
    std::fs::create_dir_all(claude.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(home.skill_path().parent().unwrap(), &claude).unwrap();
    // Emulate an unchanged older managed installation, including its marker.
    use sha2::{Digest, Sha256};
    let old = b"previous managed skill\n";
    std::fs::write(home.skill_path(), old).unwrap();
    let marker = home.skill_path().with_file_name(".sloosh-managed.json");
    let mut data: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
    use std::fmt::Write as _;
    let mut hash = String::new();
    for byte in Sha256::digest(old) {
        write!(&mut hash, "{byte:02x}").unwrap();
    }
    data["skill_sha256"] = hash.into();
    std::fs::write(marker, serde_json::to_vec(&data).unwrap()).unwrap();
    let before = sloosh(home.path(), &["skill", "status"]);
    assert!(before.status.success(), "{before:?}");
    assert_eq!(
        String::from_utf8(before.stdout)
            .unwrap()
            .matches("upgrade available")
            .count(),
        2
    );
    let install = sloosh(home.path(), &["skill", "install"]);
    assert!(install.status.success(), "{install:?}");
    assert!(
        std::fs::symlink_metadata(&claude)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let after = sloosh(home.path(), &["skill", "status"]);
    assert!(after.status.success(), "{after:?}");
    assert_eq!(
        String::from_utf8(after.stdout)
            .unwrap()
            .matches("current (managed by sloosh)")
            .count(),
        2
    );
}

#[test]
fn all_agent_selection_installs_both_supported_targets() {
    let home = TestHome::new("all-agents");

    let output = sloosh(home.path(), &["skill", "install", "--agent", "all"]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        std::fs::read_to_string(home.skill_path()).expect("Codex Skill"),
        EMBEDDED_SKILL
    );
    assert_eq!(
        std::fs::read_to_string(home.path().join(".claude/skills/sloosh/SKILL.md"))
            .expect("Claude Code Skill"),
        EMBEDDED_SKILL
    );
}
