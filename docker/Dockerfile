FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH alsvc_characterize.characterize.Characterize

# Switch to assemblyline user
USER assemblyline

# Copy Characterize service code
WORKDIR /opt/al/al_services/alsvc_characterize
COPY . .