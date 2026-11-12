FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home agent \
    && mkdir /sandbox \
    && chown agent:agent /sandbox

WORKDIR /app
COPY requirements.txt ./
COPY python-sdk ./python-sdk
RUN pip install --no-cache-dir -r requirements.txt

ENV TIKTOKEN_CACHE_DIR=/app/tiktoken-cache
RUN mkdir "$TIKTOKEN_CACHE_DIR" \
    && python -c 'import tiktoken; tiktoken.encoding_for_model("gpt-4.1")' \
    && chown -R agent:agent "$TIKTOKEN_CACHE_DIR"

COPY codeact ./codeact
COPY mcp ./mcp
COPY shared ./shared
COPY configs ./configs
COPY config.schema.json report.schema.json trace.schema.json policy.yaml mcp.json main.py ./
COPY targets/BenchmarkPython /target

WORKDIR /sandbox
