FROM python:3.12-slim

# Metadata (shows up on Docker Hub)
LABEL org.opencontainers.image.title="OpenMaskit"
LABEL org.opencontainers.image.description="Drop-in MCP proxy that keeps your secrets out of the context window"
LABEL org.opencontainers.image.url="https://github.com/MaskitMCP/openmaskit"
LABEL org.opencontainers.image.source="https://github.com/MaskitMCP/openmaskit"
LABEL org.opencontainers.image.version="0.2.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy uv binary from official image
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

# Copy dependency files and source code for installation
COPY pyproject.toml ./
COPY README.md ./
COPY src ./src

# Install dependencies and the package
ENV UV_COMPILE_BYTECODE=1
ENV UV_SYSTEM_PYTHON=1
RUN uv pip install .

# Bind to all interfaces for container networking
ENV OPENMASKIT_HOST=0.0.0.0

# Expose ports
EXPOSE 9473 9474

# Health check using the /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:9473/health').read()" || exit 1

CMD ["openmaskit"]
