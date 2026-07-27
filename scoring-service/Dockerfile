# Alpine base: pure-Python deps (Flask) ship musl wheels, so no compiler is
# needed and the final image is ~3x smaller than python:3.12-slim.
FROM python:3.12-alpine
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY ewma.py opinion.py app.py ./
EXPOSE 9100
CMD ["python", "app.py"]
