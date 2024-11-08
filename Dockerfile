FROM python:3.9

# Set the working directory in the container
WORKDIR /code

# Copy requirements.txt and install dependencies
COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . /code/

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Expose the port the app runs on
EXPOSE 8000

# Run the application
CMD ["gunicorn", "project.wsgi:application", "--bind", "0.0.0.0:8000"]