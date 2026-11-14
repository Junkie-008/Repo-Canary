# syntax=docker/dockerfile:1.7

# ---------------------------------------------------------------
# Build wheels in a throw-away stage
# ---------------------------------------------------------------
FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

COPY requirements.txt .

RUN pip wheel --wheel-dir /wheels -r requirements.txt

# ---------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    REPO_CANARY_LAB=/data/lab

RUN groupadd --gid 10001 canary \
    && useradd --uid 10001 --gid canary --create-home canary

WORKDIR /app

COPY --from=builder /wheels /wheels
COPY requirements.txt .

RUN pip install --no-index --find-links=/wheels -r requirements.txt \
    && rm -rf /wheels

COPY --chown=canary:canary scripts ./scripts
COPY --chown=canary:canary index.html ./
COPY --chown=canary:canary vendor ./vendor
COPY --chown=canary:canary known_hashes.example.txt ./
COPY --chown=canary:canary docker/entrypoint.sh /usr/local/bin/entrypoint.sh

RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && mkdir -p /data/lab \
    && chown -R canary:canary /data /app

USER canary

EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["engine"]
