provider "minikube" {
}

resource "minikube" "cluster" {
  //  disk_size = "20g"
  driver             = "virtualbox"
  kubernetes_version = "v1.17.0"
  keep_context       = false
  cache_images       = false
}

output "client_cert" {
  value = minikube.cluster.client_certificate
}

output "client_key" {
  value = minikube.cluster.client_key
}

output "ca_cert" {
  value = minikube.cluster.cluster_ca_certificate
}

