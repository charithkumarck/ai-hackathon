# One container: FastAPI serves the API and the built UI from the same origin.
# No CORS, no second service, one URL.

# ---------- stage 1: build the frontend ----------
FROM node:22-slim AS ui
WORKDIR /ui
COPY UI/package.json UI/package-lock.json ./
RUN npm ci
COPY UI/ ./
RUN npm run build

# ---------- stage 2: the app ----------
FROM python:3.12-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/app ./backend/app
COPY backend/eval ./backend/eval

# The ATT&CK bundle is ~52MB and not in git — fetch it at build time so the
# repo stays small and the image is self-contained. Parsed once at startup
# (~1s) and the raw JSON is discarded; the process holds ~60MB.
RUN mkdir -p backend/data && curl -fsSL \
    -o backend/data/enterprise-attack.json \
    https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json

# Pre-analysed demo rules. Ships with the image so the hosted demo is instant
# and costs no API quota. Optional — the app works without it.
COPY backend/data/analysis_cache.json ./backend/data/analysis_cache.json
COPY backend/eval/results.json ./backend/eval/results.json

COPY --from=ui /ui/dist ./UI/dist

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ANALYZE_WORKERS=3 \
    PORT=7860

EXPOSE 7860
WORKDIR /app/backend

# Hosts inject $PORT; default to 8000 locally.
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
