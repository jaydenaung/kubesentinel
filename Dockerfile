FROM python:3.11-slim

# TARGETARCH is set automatically by buildx (amd64 or arm64)
ARG TARGETARCH=amd64

# Pin tool versions — update these when upgrading dependencies
ARG TRIVY_VERSION=0.51.4
ARG HELM_VERSION=3.14.4

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
    && \
    # kubectl — fetch latest stable, architecture-aware
    KUBECTL_VERSION=$(curl -fsSL https://dl.k8s.io/release/stable.txt) && \
    curl -fsSL "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${TARGETARCH}/kubectl" \
        -o /usr/local/bin/kubectl && \
    chmod +x /usr/local/bin/kubectl && \
    # trivy — download pinned release binary directly (no mutable install scripts)
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -o /tmp/trivy.tar.gz && \
    tar xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy && \
    rm /tmp/trivy.tar.gz && \
    trivy --version && \
    # helm — download pinned release binary directly (no mutable install scripts)
    curl -fsSL "https://get.helm.sh/helm-v${HELM_VERSION}-linux-${TARGETARCH}.tar.gz" \
        -o /tmp/helm.tar.gz && \
    tar xzf /tmp/helm.tar.gz -C /tmp && \
    mv /tmp/linux-${TARGETARCH}/helm /usr/local/bin/helm && \
    rm -rf /tmp/helm.tar.gz /tmp/linux-${TARGETARCH} && \
    helm version && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as non-root — never run a security scanner as root
RUN groupadd -r kubesentinel && \
    useradd -r -g kubesentinel -s /sbin/nologin kubesentinel && \
    mkdir -p /app/data && \
    chown -R kubesentinel:kubesentinel /app

USER kubesentinel

VOLUME ["/app/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/')" || exit 1

CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8000"]
