Working config, SQL, and page for [APPLICATION.md](../../APPLICATION.md).

Create the database, apply [schema.sql](schema.sql), then start the server from this directory so `./page.html` and `./static` resolve. Postgres can be the one in [pgo/docker-compose.yml](../../pgo/docker-compose.yml) once port 5432 is published, or any server you already run.

```bash
createdb easyrest_app
psql -v ON_ERROR_STOP=1 -d easyrest_app -f schema.sql
easyrest-server -config config.yaml
```
