FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api.py .

VOLUME /data

EXPOSE 8000

HEALTHCHECK --interval=60s --timeout=5s --retries=3 \
  CMD python -c "import requests; r=requests.get('http://localhost:8000/health'); r.raise_for_status()"

CMD ["python", "api.py"]
