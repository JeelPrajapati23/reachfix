# reachfix API + demo page, deployed on Render from ghcr.io. CI (.github/workflows/ci.yml) builds
# and pushes this image and triggers the Render deploy on every code change to main. data/ is
# gitignored, so the build outputs come from the reachfix-data image (see Dockerfile.data).
# Local build and check:
#   docker build -t ghcr.io/jeelprajapati23/reachfix .
#   docker run --rm -p 7860:7860 --env-file .env ghcr.io/jeelprajapati23/reachfix
# GROQ_API_KEY comes from the environment (host secrets); no key is baked in. HF_TOKEN is optional:
# the default index's queries are embedded locally.
ARG DATA_IMAGE=ghcr.io/jeelprajapati23/reachfix-data:latest
FROM ${DATA_IMAGE} AS data

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim
LABEL org.opencontainers.image.source=https://github.com/JeelPrajapati23/reachfix

# Non-root; the live OSV / registry caches are written under data/raw/.
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/app/.venv/bin:$PATH \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1
WORKDIR /home/user/app

# Dependencies first, so code/data changes don't reinstall them.
COPY --chown=user pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --frozen --no-dev --no-install-project

# Query embeddings run locally (retrieval/embeddings.py): bake the ONNX MiniLM (~90 MB) into the
# image so a cold start doesn't download it from the Hugging Face Hub.
ENV FASTEMBED_CACHE_PATH=/home/user/app/.cache/fastembed
RUN python -c "from fastembed import TextEmbedding; TextEmbedding('sentence-transformers/all-MiniLM-L6-v2')"

# Only what the API loads (api/resources.py): graph, node lookup, advisory chunks + index, releases.
COPY --from=data --chown=user /depgraph/ ./data/processed/depgraph/

COPY --chown=user src ./src
COPY --chown=user schema ./schema
COPY --chown=user config ./config
RUN uv sync --frozen --no-dev

# /query spends Groq tokens shared by every visitor (see api/ratelimit.py).
ENV REACHFIX_QUERY_LIMIT_PER_IP_HOUR=10 \
    REACHFIX_QUERY_LIMIT_PER_DAY=100

# The commit this image was built from, reported by /health (CI waits on it after a deploy).
ARG REACHFIX_VERSION=dev
ENV REACHFIX_VERSION=${REACHFIX_VERSION}

# Render sets PORT itself; 7860 is the local default.
ENV PORT=7860
EXPOSE 7860
CMD ["reachfix", "--host", "0.0.0.0"]
