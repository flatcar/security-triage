from security_triage.env import load_dotenv


def test_load_dotenv_sets_values_without_overriding_existing(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# local config\n"
        "GITHUB_TOKEN=from-file\n"
        'GITHUB_MODELS_MODEL="openai/gpt-5" # inline comment\n'
        "export GITHUB_MODELS_API_VERSION=2022-11-28\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_TOKEN", "from-shell")
    monkeypatch.delenv("GITHUB_MODELS_MODEL", raising=False)
    monkeypatch.delenv("GITHUB_MODELS_API_VERSION", raising=False)

    loaded = load_dotenv(env_file)

    assert loaded == {
        "GITHUB_MODELS_MODEL": "openai/gpt-5",
        "GITHUB_MODELS_API_VERSION": "2022-11-28",
    }
    assert loaded.get("GITHUB_TOKEN") is None


def test_load_dotenv_override_replaces_existing(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("GITHUB_TOKEN=from-file\n", encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "from-shell")

    loaded = load_dotenv(env_file, override=True)

    assert loaded == {"GITHUB_TOKEN": "from-file"}
