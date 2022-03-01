ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

# Set service to be run
ENV SERVICE_PATH characterize.Characterize

# Switch to root user
USER root

# Install apt dependencies
COPY pkglist.txt pkglist.txt
RUN apt-get update && apt-get install -y < pkglist.txt && rm -rf /var/lib/apt/lists/*

# Switch to assemblyline user
USER assemblyline

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy Characterize service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.2.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
