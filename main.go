package main

import (
	"github.com/Ranger-X/terraform-provider-minikube/minikube"
	"github.com/hashicorp/terraform/plugin"
	"github.com/hashicorp/terraform/terraform"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: func() terraform.ResourceProvider {
			return minikube.Provider()
		},
	})
}
