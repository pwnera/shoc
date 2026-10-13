# One image, two roles: `shoc serve` and `shoc worker`.
# Base images are pinned by digest; Renovate moves the pins (docker:pinDigests).
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build
WORKDIR /src
RUN pip install --no-cache-dir hatchling
# constraints.txt is optional: release.yml writes the versions its SBOM was
# taken from, so the image installs those and not whatever resolves that day.
COPY pyproject.toml README.md constraints.tx[t] ./
COPY shoc ./shoc
COPY content ./content
# The recorded attack scenarios: `shoc replay --scenario` is the quick
# start's first proof that any of this works, so it has to be in the image.
COPY evals/scenarios ./evals/scenarios
# Each shipped rule's fixtures, for the Detection Engineer's gate (D77).
COPY tests/fixtures/rules ./tests/fixtures/rules
RUN python -m hatchling build -t wheel && touch constraints.txt

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
LABEL org.opencontainers.image.title="shoc" \
      org.opencontainers.image.description="Headless, AI-first, 24/7 agentic SOC" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/pwnera/shoc"
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN useradd --system --create-home --uid 10001 shoc
COPY --from=build /src/dist/*.whl /src/constraints.txt /tmp/
# SHOC_EXTRAS=databricks or snowflake adds that warehouse's connector (D131).
ARG SHOC_EXTRAS=""
RUN pip install --no-cache-dir -c /tmp/constraints.txt "$(ls /tmp/*.whl)${SHOC_EXTRAS:+[$SHOC_EXTRAS]}" \
  && rm /tmp/*.whl /tmp/constraints.txt
USER shoc
WORKDIR /home/shoc
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
ENTRYPOINT ["shoc"]
CMD ["serve", "--host", "0.0.0.0"]
