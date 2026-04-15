FROM python:3.11-slim

# Scapy needs libpcap and net tools
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    net-tools \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Daphne serves Django Channels over ASGI
CMD ["daphne", "-b", "0.0.0.0", "-p", "8000", "config.asgi:application"]
