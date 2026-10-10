# The tag must match the Playwright version pinned in requirements.txt (1.63.0): the image ships
# the browsers for exactly that version.
FROM mcr.microsoft.com/playwright/python:v1.63.0-noble

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# The code lives in /app/analyzer so that main.py's DATA_DIR (../data) is /app/data,
# the folder docker-compose mounts from the host.
WORKDIR /app/analyzer
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

# An unprivileged user with a fixed id, so the host's data folder can be given to it.
RUN useradd --uid 10001 --create-home tripwire \
    && mkdir -p /app/data \
    && chown tripwire /app/data
USER tripwire

EXPOSE 8001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
