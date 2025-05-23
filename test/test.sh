#!/bin/bash -eux

date --iso-8601=seconds

SEPOLIA=11155111
RPC_URI='https://sepolia.drpc.org'

TXFILE=tx.json

safe inspect \
  --safe "0xb6e46b8Ad163C68d736Ec4199F43033B43379c70" \
  --rpc "${RPC_URI}" \
  ;

safe build tx \
  --safe "0xb6e46b8Ad163C68d736Ec4199F43033B43379c70" \
  --chain-id $SEPOLIA \
  --version "1.4.1" \
  --nonce 5 \
  --to "0x56dF1E32E4DbDb5F2e299B8Db4Bf124d0dd78391" \
  --value "0.00444" \
  --output ${TXFILE} \
  ;

safe hash <$TXFILE

safe sign \
  --keyfile alice.key \
  --output sig-alice.json \
  <$TXFILE \
  ;

safe sign \
  --keyfile bob.key \
  --output sig-bob.json \
  <$TXFILE \
  ;

safe exec \
  --keyfile alice.key \
  --signature sig-alice.json \
  --signature sig-bob.json \
  --rpc "${RPC_URI}" \
  <$TXFILE \
  ;
