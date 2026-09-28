FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit libewf2 ewf-tools libimage-exiftool-perl tshark yara binutils file ca-certificates \
    testdisk scalpel \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system dfip && useradd --system --gid dfip --uid 10001 dfip
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app ./app
COPY rules ./rules
COPY tests ./tests
COPY pytest.ini .
RUN mkdir -p /app/storage/evidence/original /app/storage/analysis/recovered /app/storage/analysis/carved /app/storage/reports \
    && chown -R dfip:dfip /app
USER dfip
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]
