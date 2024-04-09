#!/bin/bash
export KUBECONFIG=/etc/kubernetes/admin.conf

echo "###start to stop csvnode-ra and its service"
cd /home/tcwg/workspace-mhz/csv-node/launch-container
kubectl delete -f csvnode.yaml

