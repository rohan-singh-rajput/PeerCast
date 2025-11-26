#!/bin/sh

wait_for() {
    host="$1"
    port="$2"
    
    echo "Waiting for $host:$port..."
    
    while ! nc -z $host $port; do
      sleep 1
    done
    
    echo "$host:$port is available"
}

wait_for db 5432
wait_for redis 6379
wait_for rabbitmq 5672

python manage.py migrate
python manage.py runserver 0.0.0.0:8000