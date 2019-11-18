1. Собираем образы для peer - DOCKER_DYNAMIC_LINK=true GO_TAGS+=" pluginsenabled" make peer-docker
   и orderer (или берем их из images)
2. В docker-compose привязываем папку, где находится плагин к /etc/hyperledger/fabric/plugins
3. Стартуем сетку, используя configtxgen и configtx.yaml, где добавлены наши endorser's