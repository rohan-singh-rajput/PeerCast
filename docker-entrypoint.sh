#!/bin/sh

# Function to wait for a service
wait_for() {
    host="$1"
    port="$2"
    
    echo "Waiting for $host:$port..."
    
    while ! nc -z "$host" "$port"; do
        sleep 1
    done
    
    echo "$host:$port is available"
}

# Wait for required services
wait_for db 5432
wait_for redis 6379

# Run migrations
python manage.py makemigrations
python manage.py migrate

# Start the application
python manage.py runserver 0.0.0.0:8000
