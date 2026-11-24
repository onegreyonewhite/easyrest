# Ping-pong embed example

One process runs the EasyREST embed server and a background ping task. The ping service `GET`s `http://127.0.0.1:8091/restapi/v1/game/pong/`. The embed `pong` view writes the body `pong`.

## Run locally

From this directory:

```bash
go run ./cmd
```

`GET /health` returns `OK`. The ping task logs `ping: pong` every few seconds. Press Ctrl+C to stop the HTTP server and the ping task together.

## Layout

| File | Role |
| --- | --- |
| `config.yaml` | Minimal public restapi with the `pong` view |
| `pong.go` | `PongView` and `EmbedOptions` for `embed.Run` |
| `ping.go` | `RunPing` client loop |
| `cmd/main.go` | `embed.Run` with sqlite, view, and ping service |

## Tests

```bash
go test ./... -count=1
```

`TestPingReceivesPong` starts `embed.Serve` on a random port and checks the view returns `pong`.

A view that must commit several database calls together uses `call.Plugins.Begin`. See [Embed](../../embed/README.md#shared-transaction).