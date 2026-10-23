//! Compiler acceptance and exact diagnostic contracts for the public macros.

use std::{
    error::Error,
    fmt::Write,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use sonic_rs::{JsonValueTrait, Value};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

struct CompilerFixtures {
    workspace: PathBuf,
    manifest: PathBuf,
    macro_root: PathBuf,
}

impl CompilerFixtures {
    fn new(fixtures: &[PathBuf]) -> TestResult<Self> {
        let macro_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = macro_root
            .parent()
            .and_then(Path::parent)
            .ok_or("missing workspace directory")?
            .to_path_buf();
        let project = workspace
            .join("target/compiler-fixtures/projects")
            .join(std::process::id().to_string());
        fs::create_dir_all(&project)?;
        let mut text = String::from(
            "[workspace]\n[package]\nname = \"nexora-compiler-fixtures\"\nversion = \
             \"0.0.0\"\nedition = \"2024\"\nautobins = false\n[profile.dev]\ndebug = \
             false\n[dependencies]\n",
        );
        for name in ["nexora", "nexora-macros", "nexora-proto"] {
            writeln!(
                text,
                "{name} = {{ path = {} }}",
                quoted_path(&workspace.join("crates").join(name))?
            )?;
        }
        let root_manifest = fs::read_to_string(workspace.join("Cargo.toml"))?;
        let sonic = root_manifest
            .lines()
            .find(|line| line.starts_with("sonic-rs = "))
            .ok_or("workspace must declare sonic-rs")?;
        writeln!(text, "{sonic}")?;
        for fixture in fixtures {
            writeln!(
                text,
                "[[bin]]\nname = {}\npath = {}",
                sonic_rs::to_string(&fixture_name(fixture)?)?,
                quoted_path(fixture)?
            )?;
        }
        let manifest = project.join("Cargo.toml");
        fs::write(&manifest, text)?;
        // Retain the workspace's exact registry and upstream Git revisions.
        fs::copy(workspace.join("Cargo.lock"), project.join("Cargo.lock"))?;
        Ok(Self {
            workspace,
            manifest,
            macro_root,
        })
    }

    fn check(&self, fixture: &Path) -> TestResult {
        let name = fixture_name(fixture)?;
        let output = Command::new(env!("CARGO"))
            .current_dir(&self.workspace)
            .args([
                "check",
                "--offline",
                "--message-format=json",
                "--manifest-path",
            ])
            .arg(&self.manifest)
            .args(["--bin", name])
            .env(
                "CARGO_TARGET_DIR",
                self.workspace.join("target/compiler-fixtures/build"),
            )
            .env("CARGO_TERM_COLOR", "never")
            .output()?;
        let stdout = String::from_utf8(output.stdout)?;
        let stderr = String::from_utf8(output.stderr)?;
        if name.starts_with("pass_") {
            if !output.status.success() {
                return Err(format!("{name} failed to compile:\n{stdout}\n{stderr}").into());
            }
            return Ok(());
        }
        if output.status.success() {
            return Err(format!("{name} unexpectedly compiled").into());
        }
        let mut diagnostics = String::new();
        for line in stdout.lines() {
            let message: Value = sonic_rs::from_str(line)?;
            if message["reason"].as_str() == Some("compiler-message")
                && message["target"]["name"].as_str() == Some(name)
                && message["message"]["level"].as_str() == Some("error")
            {
                diagnostics.push_str(
                    message["message"]["rendered"]
                        .as_str()
                        .ok_or("compiler diagnostic has no rendered text")?,
                );
            }
        }
        let prefix = format!("{}/", self.macro_root.display());
        let actual = diagnostics.replace(&prefix, "");
        let expected = fs::read_to_string(fixture.with_extension("stderr"))?;
        if actual.trim() != expected.trim() {
            return Err(format!(
                "{name} diagnostic mismatch:\nexpected:\n{expected}\nactual:\n{actual}\n{stderr}"
            )
            .into());
        }
        Ok(())
    }
}

fn quoted_path(path: &Path) -> TestResult<String> {
    Ok(sonic_rs::to_string(
        path.to_str().ok_or("non-UTF-8 fixture path")?,
    )?)
}

fn fixture_name(path: &Path) -> TestResult<&str> {
    path.file_stem()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "invalid fixture name".into())
}

#[test]
fn integration_scenario_compile_time_macro_contracts() -> TestResult {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/ui");
    let mut fixtures = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().is_some_and(|extension| extension == "rs") {
            let name = fixture_name(&path)?;
            if name.starts_with("pass_") || name.starts_with("fail_") {
                fixtures.push(path);
            }
        }
    }
    fixtures.sort();
    if fixtures.is_empty() {
        return Err("compiler fixtures must not be empty".into());
    }
    let compiler = CompilerFixtures::new(&fixtures)?;
    for fixture in fixtures {
        compiler.check(&fixture)?;
    }
    Ok(())
}
