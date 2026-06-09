# syntax=docker/dockerfile:1.7

FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:0.11.19 /uv /uvx /usr/local/bin/

WORKDIR /app

# Cache deps separately from source so editing tfatp/ doesn't invalidate
# the dep install layer.
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev

COPY tfatp ./tfatp
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev


FROM python:3.13-slim AS runtime

# Non-root user with a stable uid so a host bind-mount onto
# /var/lib/tfatp has predictable ownership. Pick 10001 because it's
# outside both the system (0-99) and default-user (1000-1999) ranges
# most distros use.
RUN groupadd --system --gid 10001 tfatp && \
    useradd --system --uid 10001 --gid tfatp \
            --home /var/lib/tfatp --shell /sbin/nologin tfatp

# State directory: writable bind mount goes here. token.json and
# (when using OAuth) client_secret.json live in this dir. The config
# inside the container should point at /var/lib/tfatp/token.json and
# /var/lib/tfatp/client_secret.json (or service_account.json for DWD).
RUN mkdir -p /etc/tfatp /var/lib/tfatp && \
    chown tfatp:tfatp /var/lib/tfatp

VOLUME ["/var/lib/tfatp"]

WORKDIR /app
COPY --from=builder --chown=tfatp:tfatp /app /app

# Make the venv binaries available without `uv run`.
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TFATP_STATE_DIR=/var/lib/tfatp

USER tfatp

# Default entry: the single-user watcher. Override the CMD to run a
# different cli, e.g. `docker run … python -m tfatp.cli.watch_domain`.
ENTRYPOINT ["python", "-m", "tfatp"]
CMD ["/etc/tfatp/config.toml"]
