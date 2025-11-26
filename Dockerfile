# Use the official Python slim image as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory inside the container
WORKDIR /code

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

# Install Gunicorn
RUN pip install gunicorn

# Copy the entire project into the container
COPY . /code/

# Install netcat
RUN apt-get update && apt-get install -y netcat-openbsd && rm -rf /var/lib/apt/lists/*

# Create entrypoint script
RUN echo '#!/bin/sh\n\
    \n\
    # Function to wait for a service\n\
    wait_for() {\n\
    host="$1"\n\
    port="$2"\n\
    \n\
    echo "Waiting for $host:$port..."\n\
    \n\
    while ! nc -z "$host" "$port"; do\n\
    sleep 1\n\
    done\n\
    \n\
    echo "$host:$port is available"\n\
    }\n\
    \n\
    # Wait for required services\n\
    wait_for db 5432\n\
    wait_for redis 6379\n\
    \n\
    # Run migrations\n\
    python manage.py makemigrations\n\
    python manage.py migrate\n\
    \n\
    # Start the application\n\
    python manage.py runserver 0.0.0.0:8000' > /code/entrypoint.sh && \
    chmod +x /code/entrypoint.sh

# Set the entrypoint
ENTRYPOINT ["/bin/sh", "/code/entrypoint.sh"]

# Expose port 8000
EXPOSE 8000
