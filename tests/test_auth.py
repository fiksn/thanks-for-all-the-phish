import stat

from tfatp.auth import _write_token_file


def test_write_token_file_uses_owner_only_permissions(tmp_path):
    token_path = tmp_path / "token.json"

    _write_token_file(token_path, '{"token": "secret"}')

    mode = stat.S_IMODE(token_path.stat().st_mode)
    assert mode == 0o600
    assert token_path.read_text(encoding="utf-8") == '{"token": "secret"}'


def test_write_token_file_restricts_existing_broad_file(tmp_path):
    token_path = tmp_path / "token.json"
    token_path.write_text("old", encoding="utf-8")
    token_path.chmod(0o644)

    _write_token_file(token_path, '{"token": "new"}')

    mode = stat.S_IMODE(token_path.stat().st_mode)
    assert mode == 0o600
    assert token_path.read_text(encoding="utf-8") == '{"token": "new"}'
