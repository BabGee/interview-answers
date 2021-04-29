#!/bin/sh

if [ "$DATABASE" = "postgres" ]
then
    echo "Waiting for postgres..."

    while ! nc -z $SQL_HOST $SQL_PORT; do
      sleep 0.1
    done

    echo "PostgreSQL started"
fi

python manage.py flush --no-input
python manage.py migrate --no-input
python manage.py collectstatic --no-input

#generate 15 dummy data in db
python manage.py seed search --number=15

gunicorn interintel.wsgi:application --bind 0.0.0.0:8000

exec "$@"