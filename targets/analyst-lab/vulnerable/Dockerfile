FROM python:3.12.15-slim-bookworm

# Intentionally vulnerable training target. Stdlib only: nothing to install.
WORKDIR /app
COPY app.py .
RUN useradd --uid 10001 --create-home demo && chown -R demo /app
USER demo
EXPOSE 8080
ENV PYTHONUNBUFFERED=1 BIND=0.0.0.0 PORT=8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=3s CMD python -c "import urllib.request,sys;sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=2).status==200 else 1)"
CMD ["python", "app.py"]