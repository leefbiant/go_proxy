all:
	go build -o proxy_client proxy_client.go encryption.go
	go build -o proxy_server proxy_server.go encryption.go
clean:
	rm -rf proxy_client  proxy_server *.log
