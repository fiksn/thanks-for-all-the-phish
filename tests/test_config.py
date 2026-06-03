import pytest

from tfatp.config import load_config


def _write_config(path, **overrides) -> None:
    values = {
        "domain": '"example.com"',
        "user": '"user@example.com"',
        "smtp_verify": "true",
        "auto_rewrite": "false",
    }
    values.update(overrides)
    body = "\n".join(f"{key} = {value}" for key, value in values.items())
    path.write_text(f"{body}\n", encoding="utf-8")


def test_string_false_boolean_config_is_false(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, smtp_verify='"false"', auto_rewrite='"false"')

    cfg = load_config(config_path)

    assert cfg.smtp_verify is False
    assert cfg.auto_rewrite is False


def test_invalid_boolean_string_is_rejected(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, auto_rewrite='"definitely"')

    with pytest.raises(ValueError, match="auto_rewrite must be a boolean"):
        load_config(config_path)
