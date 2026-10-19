FROM postgres:15

RUN apt-get update \
 && apt-get install -y --no-install-recommends postgresql-plpython3-15 python3-cryptography \
 && rm -rf /var/lib/apt/lists/*

COPY schema.sql /docker-entrypoint-initdb.d/01-schema.sql
COPY seed.sql /docker-entrypoint-initdb.d/02-seed.sql
