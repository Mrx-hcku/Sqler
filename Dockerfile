FROM python:3.9-slim
RUN apt-get update && apt-get install -y sqlmap git && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD gunicorn -w 2 -b 0.0.0.0:$PORT app:app
