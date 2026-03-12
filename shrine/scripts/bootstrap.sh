#!/usr/bin/env bash
set -euo pipefail

if [ -f .env ]; then export $(grep -v '^#' .env | xargs); fi

: "${ADMIN1_ADDR:?}"
: "${ADMIN1_PUBKEY:?}"
: "${ADMIN2_ADDR:?}"
: "${ADMIN2_PUBKEY:?}"
: "${THRESHOLD:=2}"
: "${WITNESS1:?}"
: "${WITNESS2:?}"

PKG_OUT=$(sui client publish --gas-budget 100000000 | tee /dev/stderr)
PKG_ID=$(echo "$PKG_OUT" | sed -n 's/.*Published package: \(0x[0-9a-fA-F]*\).*/\1/p')

echo "Package = $PKG_ID"

LEDGER=$(sui client call --package $PKG_ID --module core --function init_ledger --gas-budget 50000000 | sed -n 's/.*Created object: \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)

WSET=$(sui client call --package $PKG_ID --module core --function init_witness_set --args $ADMIN1_ADDR $THRESHOLD [ $ADMIN1_ADDR, $ADMIN2_ADDR ] --gas-budget 50000000 | sed -n 's/.*Created object: \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)

REG=$(sui client call --package $PKG_ID --module core --function init_registry --gas-budget 30000000 | sed -n 's/.*Created object: \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)

NONCES=$(sui client call --package $PKG_ID --module core --function init_admin_nonces --gas-budget 30000000 | sed -n 's/.*Created object: \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)

echo "Registering admin pubkeys..."

sui client call --package $PKG_ID --module core --function register_admin_pubkey --args $WSET $ADMIN1_PUBKEY --gas-budget 10000000

sui client call --package $PKG_ID --module core --function register_admin_pubkey --args $WSET $ADMIN2_PUBKEY --gas-budget 10000000

echo "Init witness stats & registry entries..."

for W in $WITNESS1 $WITNESS2; do
  OUT=$(sui client call --package $PKG_ID --module core --function init_witness_stats --args $W --gas-budget 30000000)
  STATS_ID=$(echo "$OUT" | sed -n 's/.*Created object: \(0x[0-9a-fA-F]*\).*/\1/p' | tail -1)
  sui client call --package $PKG_ID --module core --function register_witness_stats --args $REG $W $STATS_ID --gas-budget 10000000
  echo "Registered stats for $W -> $STATS_ID"
done

echo -e "LEDGER=$LEDGER\nWSET=$WSET\nREG=$REG\nNONCES=$NONCES"

echo "Bootstrap complete. Save these IDs safely."
