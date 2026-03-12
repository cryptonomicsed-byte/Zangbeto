#!/usr/bin/env bash
set -euo pipefail

AR_TX=${1:?arweave_tx_id}

echo -n "$AR_TX" | opentimestamps stamp - > ${AR_TX}.ots

opentimestamps upgrade ${AR_TX}.ots || true

xxd -p -c 256 ${AR_TX}.ots | tr -d '\n' | awk '{print "{\"arweave_tx\":\"""$AR_TX""\",\"btc_ots\":\""$0"\"}"}'
