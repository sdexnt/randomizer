#!/bin/bash
#Building docker peer-randomizer-image with D=.build/image/peer

docker build -t fabric-peer-randomizer .build/image/peer
docker tag fabric-peer-randomizer fabric-peer-randomizer:amd64-1.4.3

docker build -t fabric-orderer-randomizer .build/image/orderer
docker tag fabric-orderer-randomizer fabric-orderer-randomizer:amd64-1.4.3

