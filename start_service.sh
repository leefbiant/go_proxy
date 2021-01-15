#docker stop proxy_svr
#docker rm proxy_svr
#docker run -itd --name proxy_svr --env LIS_PORT=5800 -p 5800:5800 proxy_server 
#
docker stop proxy_cli
docker rm proxy_cli
docker run -itd --name proxy_cli --env LIS_PORT=5700 --env SVR_ADDR=152.32.225.124:5800 -p 5700:5700 bt731001/proxy_client
