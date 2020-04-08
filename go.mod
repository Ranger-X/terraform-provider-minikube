module github.com/Ranger-X/terraform-provider-minikube

go 1.14

// go get -u github.com/jteeuwen/go-bindata/

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/docker/machine v0.16.2
	github.com/hashicorp/terraform v0.12.24
	github.com/imdario/mergo v0.3.9
	github.com/spf13/viper v1.3.2
	k8s.io/minikube v1.9.2
)

replace (
	// we need this because of google/go-containerregistry/pkg/v1/daemon undefined: client.NewClientWithOpts (https://github.com/kubernetes/minikube/pull/6073)
	github.com/docker/docker => github.com/docker/docker v1.4.2-0.20190924003213-a8608b5b67c7
	github.com/samalba/dockerclient => github.com/sayboras/dockerclient v0.0.0-20191231050035-015626177a97
	k8s.io/api => k8s.io/api v0.0.0-20200404061942-2a93acf49b83
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.0.0-20200404065651-967ad5e9a7ed
	k8s.io/apimachinery => k8s.io/apimachinery v0.17.5-beta.0.0.20200404061537-491fc9063aba
	k8s.io/apiserver => k8s.io/apiserver v0.0.0-20200404064046-48efcf09784e
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.0.0-20200404070222-f801c5a50d41
	k8s.io/client-go => k8s.io/client-go v0.17.4
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.0.0-20200404071922-436ca80b2d51
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.0.0-20200404071653-3384f3e0515c
	k8s.io/code-generator => k8s.io/code-generator v0.17.5-beta.0.0.20200404061114-f15a378f7704
	k8s.io/component-base => k8s.io/component-base v0.0.0-20200404063306-2983c2d1a1f3
	k8s.io/cri-api => k8s.io/cri-api v0.17.5-beta.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.0.0-20200404072152-7ecc01b4c5c9
	//	k8s.io/gengo => k8s.io/gengo v0.0.0-20190822140433-26a664648505
	//	k8s.io/heapster => k8s.io/heapster v1.2.0-beta.1
	//	k8s.io/klog => k8s.io/klog v0.4.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.0.0-20200404064433-ab26955ac149
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.0.0-20200404071427-bcde41511fc5
	//	k8s.io/kube-openapi => k8s.io/kube-openapi v0.0.0-20190816220812-743ec37842bf
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.0.0-20200404070714-5b9fd4a40524
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.0.0-20200404071159-3eb232be5bb9
	k8s.io/kubectl => k8s.io/kubectl v0.0.0-20200404073144-fa62e3c3993e
	k8s.io/kubelet => k8s.io/kubelet v0.0.0-20200404070936-069efc8f9881
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.0.0-20200404072447-61f1d2777755
	k8s.io/metrics => k8s.io/metrics v0.0.0-20200404065948-a6429c97a69e
	//	k8s.io/node-api => k8s.io/node-api v0.0.0-20200404072643-ebfdb5d0d07d
	//	k8s.io/repo-infra => k8s.io/repo-infra v0.0.0-20181204233714-00fe14e3d1a3
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.0.0-20200404064810-8ef12cfc2adc
//	k8s.io/sample-cli-plugin => k8s.io/sample-cli-plugin v0.0.0-20200404070450-f763b37e0e42
//	k8s.io/sample-controller => k8s.io/sample-controller v0.0.0-20200404065217-7719b71fbe5a
//	k8s.io/utils => k8s.io/utils v0.0.0-20190801114015-581e00157fb1
)
