# IPsec X-Ray - single container with API + dashboard
# docker build -t ipsec-xray . && docker run -p 8000:8000 -v xray-data:/app/data ipsec-xray
FROM node:20-slim AS webui
WORKDIR /fe
COPY frontend/package.json ./
RUN npm install --no-audit --no-fund
COPY frontend/ ./
RUN npm run build          # -> /ipsec_xray/webui (outDir is ../ipsec_xray/webui)

FROM python:3.12-slim
WORKDIR /app
ENV PYTHONUNBUFFERED=1 IPSEC_XRAY_DATA=/app/data
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY ipsec_xray/ ./ipsec_xray/
COPY models/ ./models/
COPY samples/ ./samples/
COPY --from=webui /ipsec_xray/webui ./ipsec_xray/webui
# regenerate models/samples if the image was built from a bare checkout
RUN [ -f models/traffic_rf.joblib ] || python -m ipsec_xray.ml.train; \
    [ -f samples/manifest.json ] || python -m ipsec_xray.testbed.generate
EXPOSE 8000
VOLUME ["/app/data"]
CMD ["python", "-m", "uvicorn", "ipsec_xray.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
