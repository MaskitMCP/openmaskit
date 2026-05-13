FROM python:3.12-slim

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY . .

ENV UV_COMPILE_BYTECODE=1
ENV UV_SYSTEM_PYTHON=1

RUN uv pip install .

ENV MASKIT_HOST=0.0.0.0

EXPOSE 9473 9474 3131

CMD ["maskit"]
