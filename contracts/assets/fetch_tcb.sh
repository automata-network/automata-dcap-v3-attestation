#!/bin/bash -e

function fmspc_list() {
    cat <<EOF
00606a000000
00a067110000
00906ed50000
EOF
}

cd $(dirname $0)
mkdir -p latest/tcb_info
cd latest

curl -L -o identity.json https://api.trustedservices.intel.com/sgx/certification/v3/qe/identity
fmspc_list | xargs -I{} -P 4 curl -L -o "tcb_info/{}.json" https://api.trustedservices.intel.com/sgx/certification/v3/tcb?fmspc={}