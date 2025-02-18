# Use an official Python runtime as a base image
FROM python:3.12-slim-bookworm

# Install xmlsec (used by SAML)
RUN apt-get update && apt-get install -y pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory, where the conf directory will be created (/opt/conf)
WORKDIR /opt

RUN pip install aduneoclientfedid[saml]

# Make port 443 available to the world outside this container
EXPOSE 443

# Run the web server
ENTRYPOINT ["clientfedid"]
CMD ["-host", "0.0.0.0"]