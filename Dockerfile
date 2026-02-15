FROM python:3.12-slim

LABEL org.opencontainers.image.source="https://github.com/debu-sinha/agentsec"
LABEL org.opencontainers.image.description="Security scanner for agentic AI installations"
LABEL org.opencontainers.image.licenses="Apache-2.0"

RUN pip install --no-cache-dir agentsec-ai

RUN useradd -m -u 1000 scanner
USER scanner
WORKDIR /scan

ENTRYPOINT ["agentsec"]
CMD ["scan", "/scan"]
