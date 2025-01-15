# Deployment Guide for Targon Hub Application on Kind Kubernetes Cluster

This guide outlines the steps to deploy the Targon Hub API on a local Kind Kubernetes cluster. Follow the instructions below to set up and deploy the application.

---

## **Prerequisites**

Before proceeding, ensure the following tools are installed:

- [Docker](https://docs.docker.com/get-docker/)
- [Kind](https://kind.sigs.k8s.io/)
- [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/)

---

## **Deployment Steps**

### **1. Create a Kind Cluster**

Create a local Kind Kubernetes cluster using the provided configuration file:

```bash
kind create cluster --config ./k8s-deployment/local-kind-config.yaml
```

This command initializes a Kubernetes cluster with the specified configuration (e.g., node roles, port mappings).

---

### **2. Build Docker Images**

Build the required Docker images for the application:

```bash
docker build -t manifoldlabs/targon-hub-miner-cache:temp miner-cache
docker build -t manifoldlabs/targon-hub-api:temp api
docker build -t manifoldlabs/targon-hub-vram-estimator:temp vram-estimator
```

These commands build the following images:
- **`manifoldlabs/targon-hub-miner-cache:temp`**: Miner Cache component.
- **`manifoldlabs/targon-hub-api:temp`**: API component.
- **`manifoldlabs/targon-hub-vram-estimator:temp`**: VRAM Estimator component.

---

### **3. Load Docker Images into Kind Cluster**

Load the Docker images into the Kind cluster:

```bash
kind load docker-image manifoldlabs/targon-hub-api:temp \
    manifoldlabs/targon-hub-vram-estimator:temp \
    manifoldlabs/targon-hub-miner-cache:temp
```

This ensures the Docker images are available for use within the cluster.

---

### **4. Deploy the Application**

Apply the Kubernetes deployment manifests to deploy the application:

```bash
kubectl apply -f ./k8s-deployment/deployments.yaml
```

This command applies the resources defined in the `deployments.yaml` file, including:
- Deployments
- Services
- Ingress rules (if configured)

---

### **5. Verify Deployment**

Check the status of the resources to ensure everything is running as expected:

```bash
kubectl get pods -A
kubectl get services -A
kubectl get ingress -A
```

- **Pods**: Verify all pods are in a `Running` state.
- **Services**: Confirm services are exposed correctly.
- **Ingress**: Ensure ingress rules (if configured) are applied.

---

## **Accessing the Application**

### **Using Traefik Dashboard**
If the services are exposed as NodePort, access them via `http://localhost:8080`.

### **Using Targon **
Access the application using the hostname and paths defined in the Ingress resource (e.g., `http://localhost`).

---

## **Cleaning Up**

To delete the Kind cluster and remove all resources:

```bash
kind delete cluster
```

This removes the entire cluster and all associated resources.

---

## **References**

- [Kind Documentation](https://kind.sigs.k8s.io/)
- [Kubernetes Documentation](https://kubernetes.io/docs/)
