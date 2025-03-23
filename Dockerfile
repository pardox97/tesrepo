# Use the official Python 3.11.9 Alpine base image
FROM python:3.11.9-alpine3.20

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file (if any) and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

