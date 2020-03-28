#!/bin/bash

sudo DOCKER_HOST=unix:///var/run/burrito-docker.sock docker rm -f burrito-shard-redis
sudo DOCKER_HOST=unix:///var/run/burrito-docker.sock docker run --name burrito-shard-redis -d -p 6379:6379 redis:5

sudo ./target/release/xdp_clear -i 10.1.1.6
sleep 2
sudo RUST_LOG=debug ./target/release/burrito-shard -f -b /tmp/burrito -r "redis://localhost:6379" &
sleep 2
#sudo ./target/release/kvserver -i $1 -p $2 -n $3
sudo ./target/release/kvserver -i 10.1.1.6 -p 4242 -n $3
