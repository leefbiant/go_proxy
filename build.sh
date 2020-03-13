go build -tags netgo -o proxy_client proxy_client.go encryption.go
go build -tags netgo -o proxy_server proxy_server.go encryption.go
