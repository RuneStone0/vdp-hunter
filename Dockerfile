FROM python:3.12-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY bin ./bin
COPY run.sh ./
# seed snapshot ships outside /app/data so a mounted volume cannot hide it
COPY data/programs.json ./seed/programs.json
RUN chmod +x run.sh bin/*.sh bin/*.py

EXPOSE 8110
CMD ["./run.sh"]
