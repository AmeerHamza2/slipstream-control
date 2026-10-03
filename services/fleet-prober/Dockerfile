# syntax=docker/dockerfile:1
FROM python:3.13-slim AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
# Dependencies first, from pyproject alone, so a source change does not rebuild them.
COPY pyproject.toml ./
RUN python -c "import tomllib; print('\n'.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))" > requirements.txt \
 && pip wheel --wheel-dir /wheels -r requirements.txt
COPY README.md ./
COPY src ./src
RUN pip wheel --no-deps --wheel-dir /wheels .

FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN useradd --system --uid 10001 --no-create-home prober
COPY --from=build /wheels /wheels
RUN pip install --no-index --find-links /wheels fleet-prober && rm -rf /wheels
USER 10001
EXPOSE 9101
# Liveness: a cycle (successful or not) finished within 3 intervals, read from the local
# metrics endpoint. A failing api does not make the prober unhealthy; a wedged loop does.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["python", "-m", "fleet_prober", "--healthcheck"]
# Exec form: python is PID 1 and gets SIGTERM; the in-flight cycle finishes (<= 10 s).
# Give the container a stop grace period above that (compose: stop_grace_period: 20s).
STOPSIGNAL SIGTERM
ENTRYPOINT ["python", "-m", "fleet_prober"]
