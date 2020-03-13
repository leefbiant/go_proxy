all:
	docker build -t proxy_server . -f Dockerfile_svr
	docker build -t proxy_client . -f Dockerfile_cli
clean:
	rm -rf proxy_client  proxy_server *.log
