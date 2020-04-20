FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH characterize.Characterize

# Switch to root user
USER root

# Install apt dependancies
RUN apt-get update && apt-get install -yy libimage-exiftool-perl && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install pip packages
RUN pip install --no-cache-dir --user hachoir && rm -rf ~/.cache/pip

# Copy Characterize service code
WORKDIR /opt/al_service
COPY . .