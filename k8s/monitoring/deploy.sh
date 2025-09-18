#!/bin/bash

# TSAF Monitoring Stack Deployment Script
# This script deploys the complete monitoring stack for TSAF

set -e

NAMESPACE="tsaf-monitoring"
KUBECTL_CMD="kubectl"

echo "🚀 Deploying TSAF Monitoring Stack..."

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check dependencies
if ! command_exists kubectl; then
    echo "❌ kubectl is required but not installed."
    exit 1
fi

if ! command_exists kustomize; then
    echo "⚠️  kustomize not found, using kubectl apply -k instead"
    KUSTOMIZE_CMD="kubectl apply -k"
else
    KUSTOMIZE_CMD="kustomize build . | kubectl apply -f -"
fi

# Create namespace if it doesn't exist
echo "📦 Creating namespace: $NAMESPACE"
$KUBECTL_CMD create namespace $NAMESPACE --dry-run=client -o yaml | $KUBECTL_CMD apply -f -

# Label namespace for network policies
$KUBECTL_CMD label namespace $NAMESPACE name=$NAMESPACE --overwrite

# Deploy monitoring stack
echo "🔧 Deploying monitoring components..."
if command_exists kustomize; then
    kustomize build . | $KUBECTL_CMD apply -f -
else
    $KUBECTL_CMD apply -k .
fi

# Wait for deployments to be ready
echo "⏳ Waiting for deployments to be ready..."

deployments=("prometheus" "grafana" "alertmanager")
for deployment in "${deployments[@]}"; do
    echo "Waiting for $deployment..."
    $KUBECTL_CMD wait --for=condition=available --timeout=300s deployment/$deployment -n $NAMESPACE
done

# Wait for DaemonSet to be ready
echo "Waiting for node-exporter DaemonSet..."
$KUBECTL_CMD rollout status daemonset/node-exporter -n $NAMESPACE --timeout=300s

# Check pod status
echo "📊 Checking pod status..."
$KUBECTL_CMD get pods -n $NAMESPACE

# Display service endpoints
echo ""
echo "🌐 Service Endpoints:"
echo "===================="

# Get services
services=$($KUBECTL_CMD get svc -n $NAMESPACE -o custom-columns=NAME:.metadata.name,TYPE:.spec.type,CLUSTER-IP:.spec.clusterIP,PORT:.spec.ports[0].port --no-headers)

while IFS= read -r line; do
    name=$(echo "$line" | awk '{print $1}')
    type=$(echo "$line" | awk '{print $2}')
    cluster_ip=$(echo "$line" | awk '{print $3}')
    port=$(echo "$line" | awk '{print $4}')

    if [ "$type" = "ClusterIP" ] && [ "$cluster_ip" != "None" ]; then
        echo "$name: http://$cluster_ip:$port"
    fi
done <<< "$services"

# Check for ingresses
echo ""
echo "🔗 Ingress URLs:"
echo "==============="
ingresses=$($KUBECTL_CMD get ingress -n $NAMESPACE -o custom-columns=NAME:.metadata.name,HOSTS:.spec.rules[0].host --no-headers 2>/dev/null || true)

if [ -n "$ingresses" ]; then
    while IFS= read -r line; do
        name=$(echo "$line" | awk '{print $1}')
        host=$(echo "$line" | awk '{print $2}')
        echo "$name: https://$host"
    done <<< "$ingresses"
else
    echo "No ingresses configured"
fi

# Setup port forwarding for local access
echo ""
echo "🔄 Setting up port forwarding for local access..."
echo "================================================="

# Kill existing port forwards
pkill -f "kubectl.*port-forward.*$NAMESPACE" 2>/dev/null || true

# Start port forwards in background
$KUBECTL_CMD port-forward -n $NAMESPACE svc/grafana 3000:3000 &
$KUBECTL_CMD port-forward -n $NAMESPACE svc/prometheus 9090:9090 &
$KUBECTL_CMD port-forward -n $NAMESPACE svc/alertmanager 9093:9093 &

echo "Port forwards started:"
echo "- Grafana: http://localhost:3000 (admin/admin123)"
echo "- Prometheus: http://localhost:9090"
echo "- Alertmanager: http://localhost:9093"

# Display configuration information
echo ""
echo "⚙️  Configuration:"
echo "=================="
echo "- Prometheus scrapes metrics every 15s"
echo "- Grafana has pre-configured TSAF dashboards"
echo "- Alertmanager routes alerts based on severity"
echo "- Node exporter runs on all nodes"

# Display next steps
echo ""
echo "✅ Deployment completed successfully!"
echo ""
echo "📋 Next Steps:"
echo "=============="
echo "1. Access Grafana at http://localhost:3000 (admin/admin123)"
echo "2. Import additional dashboards if needed"
echo "3. Configure alertmanager with your notification channels"
echo "4. Update prometheus scrape configs for your TSAF app"
echo "5. Set up TLS certificates for ingresses"
echo ""
echo "📚 Documentation:"
echo "- Prometheus: https://prometheus.io/docs/"
echo "- Grafana: https://grafana.com/docs/"
echo "- Alertmanager: https://prometheus.io/docs/alerting/latest/alertmanager/"
echo ""
echo "🔍 Troubleshooting:"
echo "- Check logs: kubectl logs -n $NAMESPACE <pod-name>"
echo "- View events: kubectl get events -n $NAMESPACE"
echo "- Describe resources: kubectl describe <resource> -n $NAMESPACE"

# Save port forward PIDs for cleanup
echo ""
echo "💡 To stop port forwarding:"
echo "pkill -f 'kubectl.*port-forward.*$NAMESPACE'"