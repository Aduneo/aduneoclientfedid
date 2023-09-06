# Use an official Python runtime as a base image
FROM python:3.8

RUN apt-get update && apt-get install -y libxmlsec1-dev && \
    rm -rf /var/lib/apt/lists/*
# Set the working directory
WORKDIR /usr/src/app

# Copy the current directory contents into the container at /usr/src/app
COPY . .
RUN chmod +x ./bin/entrypoint.sh && \
export VERSION=$(grep version pyproject.toml | head -n 1 | awk -F= '{ print $2 }' | tr -d ' "') && \
python -m venv myenv && \
. ./myenv/bin/activate  && \
pip install --no-cache-dir -r requirements.txt && \
python -m build && \
pip install --force-reinstall dist/aduneoclientfedid-${VERSION}-py3-none-any.whl


# Make port 80 available to the world outside this container
EXPOSE 443

# Define environment variable
ENV NAME World

# Run app.py when the container launches
#CMD ["python", "app.py"]
CMD ["/bin/bash", "./bin/entrypoint.sh"]
