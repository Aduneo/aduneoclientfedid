# Use an official Python runtime as a base image
FROM python:3.13-bookworm AS saml

RUN useradd -ms /bin/bash aduneo

# Install xmlsec (used by SAML)
RUN apt-get update && apt-get install -y pkg-config libxml2-dev libxmlsec1-dev libxmlsec1-openssl && rm -rf /var/lib/apt/lists/*

# Set the working directory, where the conf directory will be created (/app/conf)
RUN mkdir /app && chown aduneo /app
WORKDIR /app

RUN pip install aduneoclientfedid[saml]

# I don't know how to add --no-binary in the pyproject.toml
RUN pip install --force-reinstall --no-binary lxml,xmlsec lxml xmlsec

USER aduneo

# Make port 443 available to the world outside this container
EXPOSE 443

# Run the web server
ENTRYPOINT ["clientfedid"]
CMD ["-host", "0.0.0.0"]



# no-saml version, for a lighter image
# Use an official Python runtime as a base image
FROM python:3.13-slim-bookworm AS no-saml

RUN useradd -ms /bin/bash aduneo

# Set the working directory, where the conf directory will be created (/app/conf)
RUN mkdir /app && chown aduneo /app
WORKDIR /app

RUN pip install aduneoclientfedid

USER aduneo

# Make port 443 available to the world outside this container
EXPOSE 443

# Run the web server
ENTRYPOINT ["clientfedid"]
CMD ["-host", "0.0.0.0"]