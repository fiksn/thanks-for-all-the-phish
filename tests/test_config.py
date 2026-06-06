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


def test_include_exclude_users_default_empty(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path)

    cfg = load_config(config_path)

    assert cfg.include_users == ()
    assert cfg.exclude_users == ()


def test_include_users_invalid_regex_is_rejected(tmp_path):
    config_path = tmp_path / "config.toml"
    _write_config(config_path, include_users='["[unclosed"]')

    with pytest.raises(ValueError, match="include_users"):
        load_config(config_path)


def test_filter_users_include_then_exclude_precedence():
    from tfatp.directory import filter_users

    users = [
        "alice@example.com",
        "bob@example.com",
        "carol@finance.example.com",
        "cfo@finance.example.com",
        "noreply@example.com",
    ]
    # Include only finance, then drop the CFO.
    out = filter_users(
        users,
        include=(r".*@finance\.example\.com",),
        exclude=(r"cfo@finance\.example\.com",),
    )
    assert out == ["carol@finance.example.com"]


def test_filter_users_exclude_only():
    from tfatp.directory import filter_users

    users = ["alice@example.com", "noreply@example.com"]
    out = filter_users(users, exclude=(r"noreply@example\.com",))
    assert out == ["alice@example.com"]


def test_filter_users_no_filters_is_passthrough():
    from tfatp.directory import filter_users

    users = ["alice@example.com", "bob@example.com"]
    assert filter_users(users) is users  # exact pass-through, no copy


def test_filter_users_is_case_insensitive():
    from tfatp.directory import filter_users

    users = ["Alice@Example.com"]
    out = filter_users(users, exclude=(r"alice@example\.com",))
    assert out == []
