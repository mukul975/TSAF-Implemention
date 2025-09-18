#!/bin/bash

# TSAF Monitoring Stack Backup Script
# This script backs up Prometheus data, Grafana dashboards, and Alertmanager config

set -e

NAMESPACE="tsaf-monitoring"
BACKUP_DIR="/tmp/tsaf-monitoring-backup-$(date +%Y%m%d-%H%M%S)"
KUBECTL_CMD="kubectl"

echo "💾 Starting TSAF Monitoring Backup..."
echo "Backup directory: $BACKUP_DIR"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to backup ConfigMaps
backup_configmaps() {
    echo "📦 Backing up ConfigMaps..."

    configmaps=("prometheus-config" "grafana-config" "grafana-dashboards" "alertmanager-config")

    for cm in "${configmaps[@]}"; do
        if $KUBECTL_CMD get configmap $cm -n $NAMESPACE >/dev/null 2>&1; then
            echo "Backing up ConfigMap: $cm"
            $KUBECTL_CMD get configmap $cm -n $NAMESPACE -o yaml > "$BACKUP_DIR/$cm.yaml"
        else
            echo "⚠️  ConfigMap $cm not found, skipping..."
        fi
    done
}

# Function to backup Secrets
backup_secrets() {
    echo "🔐 Backing up Secrets..."

    secrets=("grafana-secret" "monitoring-secrets")

    for secret in "${secrets[@]}"; do
        if $KUBECTL_CMD get secret $secret -n $NAMESPACE >/dev/null 2>&1; then
            echo "Backing up Secret: $secret"
            $KUBECTL_CMD get secret $secret -n $NAMESPACE -o yaml > "$BACKUP_DIR/$secret.yaml"
        else
            echo "⚠️  Secret $secret not found, skipping..."
        fi
    done
}

# Function to backup PV data
backup_persistent_data() {
    echo "💿 Backing up Persistent Volume data..."

    # Prometheus data backup
    echo "Backing up Prometheus data..."
    prometheus_pod=$($KUBECTL_CMD get pods -n $NAMESPACE -l app=prometheus -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -n "$prometheus_pod" ]; then
        mkdir -p "$BACKUP_DIR/prometheus-data"
        $KUBECTL_CMD exec -n $NAMESPACE $prometheus_pod -- tar czf - -C /prometheus . > "$BACKUP_DIR/prometheus-data/prometheus-backup.tar.gz"
        echo "✅ Prometheus data backed up"
    else
        echo "⚠️  Prometheus pod not found, skipping data backup"
    fi

    # Grafana data backup
    echo "Backing up Grafana data..."
    grafana_pod=$($KUBECTL_CMD get pods -n $NAMESPACE -l app=grafana -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -n "$grafana_pod" ]; then
        mkdir -p "$BACKUP_DIR/grafana-data"
        $KUBECTL_CMD exec -n $NAMESPACE $grafana_pod -- tar czf - -C /var/lib/grafana . > "$BACKUP_DIR/grafana-data/grafana-backup.tar.gz"
        echo "✅ Grafana data backed up"
    else
        echo "⚠️  Grafana pod not found, skipping data backup"
    fi

    # Alertmanager data backup
    echo "Backing up Alertmanager data..."
    alertmanager_pod=$($KUBECTL_CMD get pods -n $NAMESPACE -l app=alertmanager -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -n "$alertmanager_pod" ]; then
        mkdir -p "$BACKUP_DIR/alertmanager-data"
        $KUBECTL_CMD exec -n $NAMESPACE $alertmanager_pod -- tar czf - -C /alertmanager . > "$BACKUP_DIR/alertmanager-data/alertmanager-backup.tar.gz"
        echo "✅ Alertmanager data backed up"
    else
        echo "⚠️  Alertmanager pod not found, skipping data backup"
    fi
}

# Function to export Grafana dashboards
export_grafana_dashboards() {
    echo "📊 Exporting Grafana dashboards..."

    grafana_pod=$($KUBECTL_CMD get pods -n $NAMESPACE -l app=grafana -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")

    if [ -n "$grafana_pod" ]; then
        mkdir -p "$BACKUP_DIR/grafana-dashboards-export"

        # Port forward to Grafana
        $KUBECTL_CMD port-forward -n $NAMESPACE $grafana_pod 3001:3000 &
        PF_PID=$!

        # Wait for port forward to be ready
        sleep 5

        # Export dashboards using Grafana API
        # Note: This requires curl and jq to be installed
        if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
            # Get API key (this is a simplified example)
            echo "Exporting dashboards via API..."

            # Get all dashboard UIDs
            dashboard_uids=$(curl -s -u admin:admin123 http://localhost:3001/api/search?type=dash-db | jq -r '.[].uid' 2>/dev/null || echo "")

            if [ -n "$dashboard_uids" ]; then
                for uid in $dashboard_uids; do
                    dashboard_json=$(curl -s -u admin:admin123 "http://localhost:3001/api/dashboards/uid/$uid" 2>/dev/null || echo "")
                    if [ -n "$dashboard_json" ]; then
                        dashboard_title=$(echo "$dashboard_json" | jq -r '.dashboard.title' | tr ' ' '_')
                        echo "$dashboard_json" > "$BACKUP_DIR/grafana-dashboards-export/${dashboard_title}_${uid}.json"
                        echo "Exported dashboard: $dashboard_title"
                    fi
                done
            fi
        else
            echo "⚠️  curl or jq not available, skipping API-based dashboard export"
        fi

        # Clean up port forward
        kill $PF_PID 2>/dev/null || true

        echo "✅ Grafana dashboards exported"
    else
        echo "⚠️  Grafana pod not found, skipping dashboard export"
    fi
}

# Function to create backup metadata
create_backup_metadata() {
    echo "📋 Creating backup metadata..."

    cat > "$BACKUP_DIR/backup-info.txt" << EOF
TSAF Monitoring Backup Information
==================================

Backup Date: $(date)
Namespace: $NAMESPACE
Kubernetes Context: $(kubectl config current-context)

Components Backed Up:
- ConfigMaps (configurations)
- Secrets (credentials)
- Persistent Volume data
- Grafana dashboards

Restoration Instructions:
1. Restore ConfigMaps: kubectl apply -f *.yaml
2. Restore Secrets: kubectl apply -f *-secret.yaml
3. Restore PV data: Extract tar.gz files to appropriate PVs
4. Import Grafana dashboards: Use Grafana UI or API

Files in this backup:
$(ls -la "$BACKUP_DIR")
EOF
}

# Function to compress backup
compress_backup() {
    echo "🗜️  Compressing backup..."

    cd $(dirname "$BACKUP_DIR")
    backup_name=$(basename "$BACKUP_DIR")
    tar czf "${backup_name}.tar.gz" "$backup_name"

    echo "✅ Backup compressed: ${backup_name}.tar.gz"
    echo "📁 Backup location: $(pwd)/${backup_name}.tar.gz"

    # Clean up uncompressed directory
    rm -rf "$backup_name"
}

# Main backup process
main() {
    echo "🚀 Starting backup process..."

    # Check if namespace exists
    if ! $KUBECTL_CMD get namespace $NAMESPACE >/dev/null 2>&1; then
        echo "❌ Namespace $NAMESPACE not found!"
        exit 1
    fi

    # Perform backups
    backup_configmaps
    backup_secrets
    backup_persistent_data
    export_grafana_dashboards
    create_backup_metadata
    compress_backup

    echo ""
    echo "✅ Backup completed successfully!"
    echo "📦 Backup file: $(pwd)/$(basename "$BACKUP_DIR").tar.gz"
    echo ""
    echo "💡 Restoration tips:"
    echo "- Keep this backup in a secure location"
    echo "- Test restoration procedure regularly"
    echo "- Consider automating this backup with a CronJob"
}

# Cleanup function
cleanup() {
    echo "🧹 Cleaning up..."
    # Kill any remaining port forwards
    pkill -f "kubectl.*port-forward.*$NAMESPACE" 2>/dev/null || true

    # Remove temporary directory if it still exists
    if [ -d "$BACKUP_DIR" ]; then
        rm -rf "$BACKUP_DIR"
    fi
}

# Set up trap for cleanup
trap cleanup EXIT

# Run main function
main "$@"