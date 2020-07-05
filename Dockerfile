##################################################

# Zippy on RHEL Universal Baseline Image (UBI) with Python 3

# To Build use: docker build -t zippy:1.0 .

# RUN ZIPPY DOCKER CONTAINER
# Replace zcDIR with the directory where zippy conf resides
# This config file is necessary and where you place your params
# If you make a change in this doc, you must restart the container

# with interactive shell to insure app starts correctly (debug mode)
# docker run -it --name zippy -v /root/zippydock/zippy.conf:/usr/local/zippy/zippy.conf -e PYTHONPATH=/opt/rh/rh-python36/root/usr/lib/python3.6/site-packages -e FLASK_ENV=development --publish 9999:9999 --restart=always zippy:1.0 bash

# or (as a daemon, production mode)
# docker run -detach --name zippy -v /root/zippydock/zippy.conf:/usr/local/zippy/zippy.conf -e PYTHONPATH=/opt/rh/rh-python36/root/usr/lib/python3.6/site-packages -e FLASK_ENV=development --publish 9999:9999 --restart=always zippy:1.0

###################################################

# Start with the official "hardened" RHEL Universal Baseline Image (UBI)
FROM python:3

# Install zippy deps
RUN /opt/rh/rh-python36/root/usr/bin/pip install flask restful netaddr
RUN apk py3-requests

# Set working directory
WORKDIR /usr/local/zippy2

# Copy zippy files to /usr/local/zippy directory
COPY zippy ./zippy

# Start zippy app
ENTRYPOINT ["python", "app.py"]
EXPOSE 9999
