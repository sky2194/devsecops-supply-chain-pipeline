FROM python:3.11-slim

# Pre-install core foundational packages that we will track
RUN pip install --no-cache-dir \
    cryptography==41.0.0 \
    requests==2.25.1 \
    urllib3==1.26.5

ENV BANK_SECURITY_MODE=strict