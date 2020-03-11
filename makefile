all:
	go build -o proxy_client proxy_client.go
	go build -o proxy_server proxy_server.go
clean:
	rm -rf proxy_client  proxy_server
