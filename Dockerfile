FROM python:3.13-slim
WORKDIR /app
COPY privacy_redaction_toolkit ./privacy_redaction_toolkit
RUN useradd --uid 10001 --create-home runner
USER runner
WORKDIR /workspace
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
ENTRYPOINT ["python", "-m", "privacy_redaction_toolkit"]
CMD ["--help"]
