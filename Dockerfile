FROM python:3.10.3-alpine

WORKDIR /rustdesk-api-server
ADD . /rustdesk-api-server

RUN apk add --no-cache \
    gcc \
    musl-dev \
    mariadb-connector-c-dev \
    pkgconfig

RUN set -ex \
    && pip install --no-cache-dir --disable-pip-version-check -r requirements.txt \
    && rm -rf /var/cache/apk/* \
    && cp -r ./db ./db_bak

ENV HOST="0.0.0.0"
ENV TZ="America/New_York"

EXPOSE 21114/tcp
EXPOSE 21114/udp

ENTRYPOINT ["sh", "run.sh"]
