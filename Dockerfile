# Use the official Python slim image as a parent image
FROM python:3.9-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 
ENV PYTHONUNBUFFERED=1 

# Set the working directory inside the container
WORKDIR /code

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt /code/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project into the container
COPY . /code/

# Copy wait-for-it.sh into the container
COPY wait-for-it.sh /code/
RUN chmod +x /code/wait-for-it.sh  # Make it executable

# Expose port 8000 to allow communication to/from this port
EXPOSE 8000

# Default command to run the Django development server (can be overridden in docker-compose.yml)
CMD ["sh", "-c", "./wait-for-it.sh db:5432 -- ./wait-for-it.sh redis:6379 -- python manage.py migrate && python manage.py runserver 0.0.0.0:8000"]
