FROM python:3.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
WORKDIR /app
RUN useradd --uid 10001 --create-home vault \
    && mkdir /encrypted \
    && chown vault:vault /encrypted
COPY pyproject.toml ./
COPY vault ./vault
RUN pip install --no-cache-dir .
USER vault
EXPOSE 8000
CMD ["uvicorn", "vault.api:create_app", "--factory", \
     "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--no-access-log", "--no-proxy-headers"]
