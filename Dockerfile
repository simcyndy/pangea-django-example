# Use an official Python runtime as a parent image
FROM python:3.9-slim-buster

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set work directory
WORKDIR /app

# Install pipenv
RUN pip install --upgrade pip
RUN pip install pipenv

# Install dependencies
COPY Pipfile Pipfile.lock /app/
RUN pipenv install --system --deploy

# Copy project
COPY . /app/

# Start the Django development server
CMD ["python", "source/manage.py", "runserver", "0.0.0.0:8000"]
