FROM python:3.13-slim-trixie

WORKDIR /app

# Instalar dependencias y ContainerLab
RUN apt-get update && \
    apt-get install -y curl && \
    bash -c "$(curl -sL https://get.containerlab.dev)" && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]