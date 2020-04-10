package minikube

import (
	"fmt"
	"k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/minikube/constants"
	"k8s.io/minikube/pkg/minikube/vmpath"
	"os/exec"
	"path"
)

func kubectlCommand(cc *config.ClusterConfig, files []string, enable bool) *exec.Cmd {
	v := constants.DefaultKubernetesVersion
	if cc != nil {
		v = cc.KubernetesConfig.KubernetesVersion
	}

	kubectlBinary := kubectlBinaryPath(v)

	kubectlAction := "apply"
	if !enable {
		kubectlAction = "delete"
	}

	args := []string{fmt.Sprintf("KUBECONFIG=%s", path.Join(vmpath.GuestPersistentDir, "kubeconfig")), kubectlBinary, kubectlAction}
	for _, f := range files {
		args = append(args, []string{"-f", f}...)
	}

	return exec.Command("sudo", args...)
}

func kubectlBinaryPath(version string) string {
	return path.Join(vmpath.GuestPersistentDir, "binaries", version, "kubectl")
}
