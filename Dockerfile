FROM python:3.11-alpine3.19
MAINTAINER "ekam.purin@um.es"
EXPOSE 8000

WORKDIR /usr/src/app

RUN apk update

COPY Pipfile Pipfile.lock ./
RUN pip install --no-cache-dir micropipenv && \
    micropipenv requirements > requirements.txt && \
    pip install --no-cache-dir -r requirements.txt && \
    pip uninstall -y micropipenv && \
    rm Pipfile Pipfile.lock requirements.txt

COPY manager ./manager

ENTRYPOINT [ "sanic", "--host", "0.0.0.0", "manager.server:manager" ]
