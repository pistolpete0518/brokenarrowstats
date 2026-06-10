FROM python:3.12-slim

WORKDIR /app

COPY outputs/ /app/outputs/
COPY work/broken_arrow_server.py /app/server.py

ENV BROKEN_ARROW_ROOT=/app/outputs
ENV HOST=0.0.0.0
ENV PORT=8080

EXPOSE 8080
VOLUME ["/app/outputs"]

CMD ["python", "server.py"]