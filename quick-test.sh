#!/bin/sh

# TODO: This file is leftover from `rockslide` and probably needs to be adapted.

export REGISTRY_ADDR=127.0.0.1:3000

if [ "x$PODMAN_IS_REMOTE" == "xtrue" ]; then
  export REGISTRY_ADDR=$(dig +short $(hostname)):3000
fi

echo "registry: ${REGISTRY_ADDR}"

podman login --tls-verify=false --username devuser --password devpw http://${REGISTRY_ADDR}
podman pull crccheck/hello-world
podman tag crccheck/hello-world ${REGISTRY_ADDR}/testing/hello:prod
podman push --tls-verify=false ${REGISTRY_ADDR}/testing/hello:prod

sleep 2

curl -v http://${REGISTRY_ADDR}/testing/hello
