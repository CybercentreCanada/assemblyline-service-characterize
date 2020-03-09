FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH characterize.Characterize

USER root

RUN apt-get update && apt-get install -yy build-essential && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Copy Characterize service code
WORKDIR /opt/al_service
COPY . .