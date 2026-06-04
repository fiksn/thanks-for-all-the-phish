import pytest

from tfatp.config import load_config


def _write_config(path, **overrides) -> None:
    values = {
        "domain": '"example.com"',
        "user": '"user@example.com"',
        "smtp_verify": "true",
    }
    values.update(overrides)
    body = "\n".join(f"{key} = {value}" for key, value in values.items())
    path.write_text(f"{body}\n", encoding="utf-8")


def test_string_false_boolean_config_is_false(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, smtp_verify='"false"')

    cfg = load_config(config_path)

    assert cfg.smtp_verify is False


def test_invalid_boolean_string_is_rejected(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, smtp_verify='"definitely"')

    with pytest.raises(ValueError, match="smtp_verify must be a boolean"):
        load_config(config_path)


def test_rewrite_only_from_rejects_invalid_regex(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, rewrite_only_from='["[unclosed"]')

    with pytest.raises(ValueError, match="rewrite_only_from"):
        load_config(config_path)


def test_rewrite_only_from_defaults_to_empty(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path)

    cfg = load_config(config_path)

    assert cfg.rewrite_only_from == ()
