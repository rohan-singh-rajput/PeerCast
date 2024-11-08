# Dockerfile for Django services
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source code
COPY . /app/

# Collect static files and run migrations
RUN python manage.py collectstatic --noinput
RUN python manage.py migrate

# Expose port
EXPOSE 8000

# Run Django development server
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"]
