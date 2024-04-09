#!/bin/bash
export KUBECONFIG=/etc/kubernetes/admin.conf

echo "###start to launch csvnode-ra and its service with CSV-enabled VM"
cd /home/tcwg/workspace-mhz/csv-node/launch-container
kubectl apply -f csvnode.yaml
output=$(kubectl get pods | grep "csvnode-ra")
if [ -z "$output" ]; then
	echo "pod csvnode-ra is not exist!"
	exit 1
fi

echo "current pod state: $output"

while ! echo "$output" | grep "Running"; do
	sleep 3
	echo "current pod state: $output"
	output=$(kubectl get pods | grep "csvnode-ra")
done
