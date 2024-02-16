#!/bin/bash

docker stop nginx
docker rm nginx

docker run --name nginx -v `pwd`/nginx.conf:/etc/nginx/nginx.conf:ro -v `pwd`/cert:/cert -p 8443:8443 -d nginx
