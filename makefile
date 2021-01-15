all:
	docker build -t bt731001/proxy_server . -f Dockerfile_svr
	docker build -t bt731001/proxy_client . -f Dockerfile_cli
