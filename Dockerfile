FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH characterize.Characterize

# Switch to assemblyline user
USER assemblyline

# Copy Characterize service code
WORKDIR /opt/al_service
COPY . .