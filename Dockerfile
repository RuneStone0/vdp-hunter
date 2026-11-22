FROM golang:1.23-bookworm AS goscan
WORKDIR /src
COPY go ./go
RUN cd go && CGO_ENABLED=0 go build -o /out/scan ./cmd/scan \
    && CGO_ENABLED=0 go build -o /out/zonex ./cmd/zonex \
    && CGO_ENABLED=0 go build -o /out/czds ./cmd/czds

FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends curl gzip \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY bin ./bin
COPY run.sh ./
# the sweep binaries are built here, so the service carries its own scanner
COPY --from=goscan /out/ ./bin/go/
# seed snapshot ships outside /app/data so a mounted volume cannot hide it
COPY data/programs.json ./seed/programs.json
# the TLD list ships outside /app/data too: the volume shadows that path
COPY data/czds_tlds.txt ./seed/czds_tlds.txt
RUN chmod +x run.sh bin/*.sh bin/*.py bin/go/*

EXPOSE 8110
CMD ["./run.sh"]
