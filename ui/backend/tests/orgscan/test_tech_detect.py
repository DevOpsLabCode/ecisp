from app.orgscan import tech_detect


def test_trivy_always_detected_regardless_of_content(tmp_path):
    assert tech_detect.detect(tmp_path) == ["trivy"]


def test_detects_python_via_requirements_txt(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask\n")
    (tmp_path / "app.py").write_text("print('hi')\n")
    assert tech_detect.detect(tmp_path) == ["bandit", "semgrep", "trivy"]


def test_detects_bandit_from_bare_py_file_without_manifest(tmp_path):
    (tmp_path / "script.py").write_text("import os\n")
    assert "bandit" in tech_detect.detect(tmp_path)


def test_detects_checkov_from_terraform(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    detected = tech_detect.detect(tmp_path)
    assert "checkov" in detected
    assert "semgrep" in detected


def test_detects_checkov_from_dockerfile(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM python:3.11\n")
    assert "checkov" in tech_detect.detect(tmp_path)


def test_checkov_ignores_unrelated_yaml(tmp_path):
    (tmp_path / "config.yml").write_text("some: setting\nnot: iac\n")
    assert "checkov" not in tech_detect.detect(tmp_path)


def test_checkov_detects_kubernetes_yaml_by_content(tmp_path):
    (tmp_path / "deployment.yaml").write_text("apiVersion: apps/v1\nkind: Deployment\n")
    assert "checkov" in tech_detect.detect(tmp_path)


def test_detects_gosec_from_go_mod(tmp_path):
    (tmp_path / "go.mod").write_text("module example.com/app\n")
    assert "gosec" in tech_detect.detect(tmp_path)


def test_detects_spotbugs_from_pom_xml(tmp_path):
    (tmp_path / "pom.xml").write_text("<project></project>\n")
    assert "spotbugs" in tech_detect.detect(tmp_path)


def test_detects_eslint_from_package_json(tmp_path):
    (tmp_path / "package.json").write_text("{}\n")
    assert "eslint_security" in tech_detect.detect(tmp_path)


def test_detects_eslint_from_bare_js_file(tmp_path):
    (tmp_path / "index.js").write_text("console.log('hi');\n")
    assert "eslint_security" in tech_detect.detect(tmp_path)


def test_detects_brakeman_from_gemfile(tmp_path):
    (tmp_path / "Gemfile").write_text('source "https://rubygems.org"\n')
    assert "brakeman" in tech_detect.detect(tmp_path)


def test_detects_security_code_scan_from_csproj(tmp_path):
    (tmp_path / "app.csproj").write_text("<Project></Project>\n")
    assert "security_code_scan" in tech_detect.detect(tmp_path)


def test_empty_repo_only_detects_trivy(tmp_path):
    # SCA/secrets scanning applies regardless of language -- trivy is the
    # one scanner with no indicator-file gate, see tech_detect.detect()'s
    # comment on it.
    (tmp_path / "README.md").write_text("hello\n")
    assert tech_detect.detect(tmp_path) == ["trivy"]


def test_ignores_vendored_and_git_directories(tmp_path):
    vendor_dir = tmp_path / "node_modules" / "pkg"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "index.js").write_text("module.exports = {};\n")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "config").write_text("[core]\n")
    assert tech_detect.detect(tmp_path) == ["trivy"]


def test_max_depth_limits_the_walk(tmp_path):
    deep = tmp_path
    for i in range(tech_detect.MAX_SCAN_DEPTH + 3):
        deep = deep / f"level{i}"
    deep.mkdir(parents=True)
    (deep / "requirements.txt").write_text("flask\n")
    assert tech_detect.detect(tmp_path) == ["trivy"]  # too deep to be found by anything else
