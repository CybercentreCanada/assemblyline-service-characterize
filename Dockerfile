FROM cccs/assemblyline-v4-service-base:latest

ENV SERVICE_PATH characterize.Characterize

# Switch to root user
USER root

# Install apt dependancies
RUN apt-get update && apt-get install -yy libimage-exiftool-perl git && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install pip packages
# Using fork temporarily while https://github.com/vstinner/hachoir/pull/69 is reviewed
RUN pip install --no-cache-dir --user git+https://github.com/cccs-rs/hachoir && rm -rf ~/.cache/pip

# Copy Characterize service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
