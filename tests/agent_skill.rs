#[cfg(unix)]
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
        #[cfg(unix)]
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create test HOME");
        #[cfg(windows)]
        std::fs::create_dir(&path).expect("create test HOME");
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
fn embedded_skill_explains_split_cli_and_desktop_approval() {
    assert!(EMBEDDED_SKILL.contains("optional desktop"));
    assert!(EMBEDDED_SKILL.contains("control plane and does not install the CLI"));
    assert!(EMBEDDED_SKILL.contains("Setup and Security"));
    assert!(EMBEDDED_SKILL.contains("Always Allow"));
    assert!(EMBEDDED_SKILL.contains("command-line-only installs"));
    assert!(EMBEDDED_SKILL.contains("sloosh approve <ID>"));
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
