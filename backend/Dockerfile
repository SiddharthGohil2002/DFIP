FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 DEBIAN_FRONTEND=noninteractive
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    sleuthkit libewf2 ewf-tools libimage-exiftool-perl tshark yara binutils file ca-certificates \
    testdisk scalpel tzdata tzdata-legacy poppler-utils 7zip regripper pff-tools sqlite3 \
    ffmpeg tesseract-ocr tesseract-ocr-eng clamav clamav-freshclam osslsigncode upx-ucl \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system dfip && useradd --system --gid dfip --uid 10001 dfip
# capa (Mandiant), the standalone release with its rules built in, pinned by version and SHA-256
RUN python -c "import urllib.request; urllib.request.urlretrieve('https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip', '/tmp/capa.zip')" \
    && echo "07800a1d20a21eb18fc98716e2ae81b668e0c9a04defd588c8aa17ea3d3281e4  /tmp/capa.zip" | sha256sum -c - \
    && python -c "import zipfile; zipfile.ZipFile('/tmp/capa.zip').extract('capa', '/usr/local/bin')" \
    && chmod 0755 /usr/local/bin/capa && rm /tmp/capa.zip
COPY requirements.txt .
RUN pip install -r requirements.txt
# impacket's ESE reader is the tests' independent check of SRUM and Windows Search (only that part is used)
RUN pip install --no-deps impacket==0.13.1
COPY app ./app
COPY rules ./rules
COPY tests ./tests
COPY pytest.ini .
RUN mkdir -p /app/storage/evidence/original /app/storage/analysis/recovered /app/storage/analysis/carved /app/storage/reports \
    && chown -R dfip:dfip /app
USER dfip
EXPOSE 8000
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000","--proxy-headers"]
