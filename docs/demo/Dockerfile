FROM node:22-slim

# Install system dependencies (git needed for openclaw npm install)
RUN apt-get update && apt-get install -y git python3 python3-pip python3-venv && \
    rm -rf /var/lib/apt/lists/*

# Install OpenClaw
RUN npm install -g openclaw

# Install agentsec
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install agentsec-ai

# Create a test user
RUN useradd -m testuser
USER testuser
WORKDIR /home/testuser

CMD ["bash"]
