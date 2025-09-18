#!/bin/bash
set -e

# TSAF Kubernetes Deployment Script
echo "🚀 TSAF Kubernetes Deployment"
echo "=============================="

# Configuration
NAMESPACE="tsaf"
IMAGE_TAG="${IMAGE_TAG:-latest}"
REGISTRY="${REGISTRY:-localhost:5000}"
IMAGE_NAME="${REGISTRY}/tsaf:${IMAGE_TAG}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl is not installed"
        exit 1
    fi

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi

    # Check cluster connectivity
    if ! kubectl cluster-info &> /dev/null; then
        log_error "Cannot connect to Kubernetes cluster"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."

    # Navigate to project root
    cd "$(dirname "$0")/.."

    # Build production image
    docker build -f docker/Dockerfile.prod -t "${IMAGE_NAME}" .

    if [ $? -eq 0 ]; then
        log_success "Docker image built successfully: ${IMAGE_NAME}"
    else
        log_error "Docker image build failed"
        exit 1
    fi

    # Push to registry if not localhost
    if [[ "${REGISTRY}" != "localhost:5000" ]]; then
        log_info "Pushing image to registry..."
        docker push "${IMAGE_NAME}"

        if [ $? -eq 0 ]; then
            log_success "Image pushed to registry"
        else
            log_error "Failed to push image to registry"
            exit 1
        fi
    fi
}

# Create namespace
create_namespace() {
    log_info "Creating namespace..."

    kubectl apply -f k8s/namespace.yaml

    if [ $? -eq 0 ]; then
        log_success "Namespace created/updated"
    else
        log_error "Failed to create namespace"
        exit 1
    fi
}

# Deploy secrets
deploy_secrets() {
    log_info "Deploying secrets..."

    # Check if secrets already exist
    if kubectl get secret tsaf-secrets -n ${NAMESPACE} &> /dev/null; then
        log_warning "Secrets already exist. Use 'kubectl delete secret tsaf-secrets -n ${NAMESPACE}' to recreate."
    else
        kubectl apply -f k8s/secrets.yaml

        if [ $? -eq 0 ]; then
            log_success "Secrets deployed"
        else
            log_error "Failed to deploy secrets"
            exit 1
        fi
    fi
}

# Deploy ConfigMaps
deploy_configmaps() {
    log_info "Deploying ConfigMaps..."

    kubectl apply -f k8s/configmap.yaml

    if [ $? -eq 0 ]; then
        log_success "ConfigMaps deployed"
    else
        log_error "Failed to deploy ConfigMaps"
        exit 1
    fi
}

# Deploy database
deploy_database() {
    log_info "Deploying PostgreSQL database..."

    kubectl apply -f k8s/postgresql.yaml

    if [ $? -eq 0 ]; then
        log_success "PostgreSQL deployed"

        # Wait for database to be ready
        log_info "Waiting for PostgreSQL to be ready..."
        kubectl wait --for=condition=available --timeout=300s deployment/postgres -n ${NAMESPACE}

        if [ $? -eq 0 ]; then
            log_success "PostgreSQL is ready"
        else
            log_warning "PostgreSQL deployment timeout - continuing anyway"
        fi
    else
        log_error "Failed to deploy PostgreSQL"
        exit 1
    fi
}

# Deploy Redis
deploy_redis() {
    log_info "Deploying Redis cache..."

    kubectl apply -f k8s/redis.yaml

    if [ $? -eq 0 ]; then
        log_success "Redis deployed"

        # Wait for Redis to be ready
        log_info "Waiting for Redis to be ready..."
        kubectl wait --for=condition=available --timeout=300s deployment/redis -n ${NAMESPACE}

        if [ $? -eq 0 ]; then
            log_success "Redis is ready"
        else
            log_warning "Redis deployment timeout - continuing anyway"
        fi
    else
        log_error "Failed to deploy Redis"
        exit 1
    fi
}

# Deploy RBAC
deploy_rbac() {
    log_info "Deploying RBAC..."

    kubectl apply -f k8s/service-account.yaml

    if [ $? -eq 0 ]; then
        log_success "RBAC deployed"
    else
        log_error "Failed to deploy RBAC"
        exit 1
    fi
}

# Deploy application
deploy_application() {
    log_info "Deploying TSAF application..."

    # Update image in deployment
    sed -i.bak "s|image: tsaf:latest|image: ${IMAGE_NAME}|g" k8s/tsaf-deployment.yaml

    kubectl apply -f k8s/tsaf-deployment.yaml

    # Restore original file
    mv k8s/tsaf-deployment.yaml.bak k8s/tsaf-deployment.yaml

    if [ $? -eq 0 ]; then
        log_success "TSAF application deployed"

        # Wait for application to be ready
        log_info "Waiting for TSAF application to be ready..."
        kubectl wait --for=condition=available --timeout=600s deployment/tsaf-app -n ${NAMESPACE}

        if [ $? -eq 0 ]; then
            log_success "TSAF application is ready"
        else
            log_warning "TSAF application deployment timeout"
        fi
    else
        log_error "Failed to deploy TSAF application"
        exit 1
    fi
}

# Deploy services
deploy_services() {
    log_info "Deploying services..."

    kubectl apply -f k8s/service.yaml

    if [ $? -eq 0 ]; then
        log_success "Services deployed"
    else
        log_error "Failed to deploy services"
        exit 1
    fi
}

# Deploy ingress
deploy_ingress() {
    log_info "Deploying ingress..."

    # Check if ingress controller is available
    if kubectl get ingressclass nginx &> /dev/null; then
        kubectl apply -f k8s/ingress.yaml

        if [ $? -eq 0 ]; then
            log_success "Ingress deployed"
        else
            log_error "Failed to deploy ingress"
            exit 1
        fi
    else
        log_warning "NGINX ingress controller not found - skipping ingress deployment"
    fi
}

# Deploy autoscaling
deploy_autoscaling() {
    log_info "Deploying autoscaling..."

    kubectl apply -f k8s/hpa.yaml

    if [ $? -eq 0 ]; then
        log_success "Autoscaling deployed"
    else
        log_error "Failed to deploy autoscaling"
        exit 1
    fi
}

# Show deployment status
show_status() {
    log_info "Deployment status:"
    echo ""

    # Show pods
    echo "📦 Pods:"
    kubectl get pods -n ${NAMESPACE} -o wide
    echo ""

    # Show services
    echo "🌐 Services:"
    kubectl get services -n ${NAMESPACE}
    echo ""

    # Show ingress
    echo "🔗 Ingress:"
    kubectl get ingress -n ${NAMESPACE}
    echo ""

    # Show HPA
    echo "📈 Horizontal Pod Autoscaler:"
    kubectl get hpa -n ${NAMESPACE}
    echo ""

    # Show PVCs
    echo "💾 Persistent Volume Claims:"
    kubectl get pvc -n ${NAMESPACE}
    echo ""
}

# Get access information
show_access_info() {
    log_info "Access information:"
    echo ""

    # Get LoadBalancer IP
    EXTERNAL_IP=$(kubectl get service tsaf-service -n ${NAMESPACE} -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

    if [ -n "$EXTERNAL_IP" ]; then
        echo "🌍 External Access:"
        echo "   HTTP:  http://${EXTERNAL_IP}"
        echo "   HTTPS: https://${EXTERNAL_IP}"
        echo "   API Documentation: http://${EXTERNAL_IP}/docs"
        echo ""
    fi

    # Port forwarding instructions
    echo "🔀 Local Access (port forwarding):"
    echo "   kubectl port-forward service/tsaf-service-internal 8000:8000 -n ${NAMESPACE}"
    echo "   Then access: http://localhost:8000"
    echo ""

    # Logs
    echo "📋 View logs:"
    echo "   kubectl logs -f deployment/tsaf-app -n ${NAMESPACE}"
    echo ""
}

# Cleanup function
cleanup() {
    log_info "Cleaning up deployment..."

    kubectl delete namespace ${NAMESPACE} --ignore-not-found=true

    log_success "Cleanup completed"
}

# Main deployment function
main() {
    case "${1:-deploy}" in
        "deploy")
            check_prerequisites
            build_image
            create_namespace
            deploy_secrets
            deploy_configmaps
            deploy_rbac
            deploy_database
            deploy_redis
            deploy_application
            deploy_services
            deploy_ingress
            deploy_autoscaling
            show_status
            show_access_info
            log_success "🎉 TSAF deployment completed successfully!"
            ;;
        "cleanup")
            cleanup
            ;;
        "status")
            show_status
            show_access_info
            ;;
        "build")
            check_prerequisites
            build_image
            ;;
        *)
            echo "Usage: $0 {deploy|cleanup|status|build}"
            echo ""
            echo "Commands:"
            echo "  deploy  - Full deployment (default)"
            echo "  cleanup - Remove all resources"
            echo "  status  - Show deployment status"
            echo "  build   - Build Docker image only"
            echo ""
            echo "Environment variables:"
            echo "  IMAGE_TAG - Docker image tag (default: latest)"
            echo "  REGISTRY  - Docker registry (default: localhost:5000)"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"