#!/bin/bash

set -e
set -x

mkdir -p /tmp/burrito
sudo docker rm -f rpcbench-cli || true
sudo docker run --mount type=bind,source=/tmp/burrito/,target=/burrito -it --name rpcbench-cli -d ubuntu:20.04 /bin/bash
sudo docker cp ./target/release/bincode-pingclient rpcbench-cli:/client

if [[ $6 != "none" ]]; then
    sudo docker cp $6 rpcbench-cli:/gt
fi

RLOG="info"
#RLOG="info,rpcbench=trace,bertha=trace,tls_tunnel=trace,localname_ctl=trace"

# 1 = outdir, 2 = addr, 3 = i, 4 = reqs-per-iter, 5 = outfile, 6 = encr, 7 = burrito-root
if [[ $2 =~ ":" ]]; then 
    if [[ $6 != "none" ]]; then
        if [[ $7 != "none"  ]]; then
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $2 -w=imm $3 $4 -o="/$5.data" --encr-ghostunnel-root=/gt $7 $8
        else
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $2 -w=imm $3 $4 -o="/$5.data" --encr-ghostunnel-root=/gt $8
        fi
    else
        if [[ $7 != "none"  ]]; then
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $2 -w=imm $3 $4 -o="/$5.data" $7 $8
        else
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $2 -w=imm $3 $4 -o="/$5.data" $8
        fi
    fi

    # remote experiment. get server tracefile in 2 steps
    ssh_addr=$(echo "$2" | awk -F ':' '{print $1}')
    ssh $ssh_addr sudo docker cp rpcbench-srv:/server.trace ~/"$5.srvtrace" || true
    scp $ssh_addr:"$5.srvtrace" $1/"$5.srvtrace" || true
else
    container_ip=$(sudo docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' rpcbench-srv)
    if [[ $6 != "none" ]]; then
        if [[ $7 != "none"  ]]; then
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $container_ip:$2 -w=imm $3 $4 -o="/$5.data" --encr-ghostunnel-root=/gt $7 $8
        else
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $container_ip:$2 -w=imm $3 $4 -o="/$5.data" --encr-ghostunnel-root=/gt $8
        fi
    else
        if [[ $7 != "none"  ]]; then
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $container_ip:$2 -w=imm $3 $4 -o="/$5.data" $7 $8
        else
            sudo docker exec -e RUST_LOG=$RLOG rpcbench-cli /client \
                --addr $container_ip:$2 -w=imm $3 $4 -o="/$5.data" $8
        fi
    fi

    # local experiment. get server tracefile
    sudo docker cp rpcbench-srv:/server.trace $1/"$5.srvtrace" || true
fi
sudo docker cp rpcbench-cli:/"$5.data" $1/"$5.data"
sudo docker cp rpcbench-cli:/"$5.trace" $1/"$5.trace"

sudo docker rm -f rpcbench-cli
ps aux | grep burrito-localname | awk '{print $2}' | xargs sudo kill -9
