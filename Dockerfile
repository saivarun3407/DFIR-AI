FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.11 python3.11-venv python3-pip \
        git curl ca-certificates jq \
        libmagic1 \
    && rm -rf /var/lib/apt/lists/*

RUN python3.11 -m pip install --no-cache-dir uv

WORKDIR /workspace

COPY mcp-server/pyproject.toml mcp-server/pyproject.toml
COPY mcp-server/src mcp-server/src
RUN uv pip install --system --no-cache "./mcp-server[forensics]"

RUN useradd -u 1000 -m hound && \
    mkdir -p /input /output /corpus && \
    chown -R hound:hound /output

USER hound

CMD ["python3.11", "-m", "protocol_sift_mcp.server"]
