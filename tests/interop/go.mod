module github.com/mikluko/valiss-py/tests/interop

go 1.26.4

require (
	github.com/mikluko/valiss v0.0.0-00010101000000-000000000000
	github.com/nats-io/nkeys v0.4.16
)

require (
	github.com/nats-io/jwt/v2 v2.8.2 // indirect
	golang.org/x/crypto v0.52.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/mikluko/valiss => ../../../valiss
