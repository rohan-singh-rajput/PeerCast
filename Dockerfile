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
    && rm -rf /var/lib/apt/lists/*

# Copy and install Python dependencies
COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

# Install Gunicorn
RUN pip install gunicorn

# Copy the entire project into the container
COPY . /code/

# Copy wait-for-it.sh and ensure it's executable
COPY wait-for-it.sh /code/
RUN chmod +x /code/wait-for-it.sh

# Expose port 8000
EXPOSE 8000

# Default command for running the application with Gunicorn
CMD ["sh", "-c", "./wait-for-it.sh db:5432 -- ./wait-for-it.sh redis:6379 -- python manage.py migrate && gunicorn myproject.wsgi:application --bind 0.0.0.0:8000 --workers 3"]
