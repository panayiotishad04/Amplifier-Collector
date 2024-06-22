# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /usr/src/app

# Install system dependencies and fpdns, ntp
RUN apt-get update && \
    apt-get install -y --no-install-recommends fpdns ntp && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy the requirements file first to leverage caching
COPY requirements.txt .

# Install dependencies (this layer will be cached if requirements.txt hasn't changed)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Copy the .env file
COPY .env .env

# By default, run the help command to list available scripts
CMD ["python", "-c", "print('Available scripts: server_collection.py, amplifier_discovery.py, packet_sender.py, server_fingerprinting.py')"]
