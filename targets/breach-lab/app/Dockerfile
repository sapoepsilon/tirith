FROM python:3.12.15-slim-bookworm

# Intentionally vulnerable demo target. Stdlib only; iputils-ping gives the cmdi flaw something to run.
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY app.py .
RUN useradd --uid 10001 --create-home demo && mkdir -p /srv/data && chown -R demo /app /srv/data
USER demo
EXPOSE 8080
ENV PYTHONUNBUFFERED=1 BIND=0.0.0.0 PORT=8080 DEMO_ROOT=/srv/data
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2).status==200 else 1)"
CMD ["python", "app.py"]
