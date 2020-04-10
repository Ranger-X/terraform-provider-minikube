package minikube

import (
	"bytes"
	b64 "encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/blang/semver"
	"github.com/docker/machine/libmachine/state"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/imdario/mergo"
	"k8s.io/minikube/cmd/minikube/cmd"
	"k8s.io/minikube/pkg/minikube/bootstrapper"
	"k8s.io/minikube/pkg/minikube/cluster"
	cfg "k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/minikube/constants"
	"k8s.io/minikube/pkg/minikube/download"
	"k8s.io/minikube/pkg/minikube/driver"
	"k8s.io/minikube/pkg/minikube/exit"
	"k8s.io/minikube/pkg/minikube/kubeconfig"
	"k8s.io/minikube/pkg/minikube/localpath"
	"k8s.io/minikube/pkg/minikube/machine"
	"k8s.io/minikube/pkg/minikube/out"
	"k8s.io/minikube/pkg/minikube/registry"
	"k8s.io/minikube/pkg/minikube/translate"
	// Register drivers
	_ "k8s.io/minikube/pkg/minikube/registry/drvs"
	pkgutil "k8s.io/minikube/pkg/util"
	"k8s.io/minikube/pkg/version"
)

const clusterNotRunningStatusFlag = 1 << 1

var (
	clusterBootstrapper string = bootstrapper.Kubeadm
	profile             string = constants.DefaultClusterName
	minimumDiskSizeInMB int    = 3000
	// PSPyml is config template for create PodSecurityPolicy roles and bindings if PSP enabled for minikube
	// based on https://minikube.sigs.k8s.io/docs/tutorials/using_psp/
	PSPyml = template.Must(template.New("PSPYml-addon").Parse(`apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: privileged
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: "*"
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
spec:
  privileged: true
  allowPrivilegeEscalation: true
  allowedCapabilities:
  - "*"
  volumes:
  - "*"
  hostNetwork: true
  hostPorts:
  - min: 0
    max: 65535
  hostIPC: true
  hostPID: true
  runAsUser:
    rule: 'RunAsAny'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
---
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  readOnlyRootFilesystem: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp:privileged
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - privileged
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: psp:restricted
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
rules:
- apiGroups: ['policy']
  resources: ['podsecuritypolicies']
  verbs:     ['use']
  resourceNames:
  - restricted
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: default:restricted
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: psp:restricted
subjects:
- kind: Group
  name: system:authenticated
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: default:privileged
  namespace: kube-system
  labels:
    addonmanager.kubernetes.io/mode: EnsureExists
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: psp:privileged
subjects:
- kind: Group
  name: system:masters
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: system:nodes
  apiGroup: rbac.authorization.k8s.io
- kind: Group
  name: system:serviceaccounts:kube-system
  apiGroup: rbac.authorization.k8s.io
`))
)

type CustomConfig struct {
	PSP bool // enable PodSecurityPolicy
}

func resourceMinikube() *schema.Resource {
	return &schema.Resource{
		Create: resourceMinikubeCreate,
		Read:   resourceMinikubeRead,
		Delete: resourceMinikubeDelete,

		// https://github.com/kubernetes/minikube/blob/e098a3c4ca91f7907705a99e4e3466868afca482/cmd/minikube/cmd/start_flags.go
		Schema: map[string]*schema.Schema{
			"addons": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Enable addons. see `minikube addons list` for a list of valid addon names.",
				Elem:        &schema.Schema{Type: schema.TypeMap},
				ForceNew:    true,
				Optional:    true,
			},
			"apiserver_name": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The apiserver name which is used in the generated certificate for localkube/kubernetes.  This can be used if you want to make the apiserver available from outside the machine (default \"minikubeCA\")",
				Default:     "minikubeCA",
				ForceNew:    true,
				Optional:    true,
			},
			"cache_images": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "If true, cache docker images for the current bootstrapper and load them into the machine. (default true)",
				Default:     true,
				ForceNew:    true,
				Optional:    true,
			},
			"container_runtime": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The container runtime to be used",
				Default:     "docker",
				ForceNew:    true,
				Optional:    true,
			},
			"cpus": &schema.Schema{
				Type:        schema.TypeInt,
				Description: "Number of CPUs allocated to the minikube VM (default 2)",
				Default:     2,
				ForceNew:    true,
				Optional:    true,
			},
			"disable_driver_mounts": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "Disables the filesystem mounts provided by the VirtualBox",
				Default:     true,
				ForceNew:    true,
				Optional:    true,
			},
			"disk_size": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Disk size allocated to the minikube VM (format: <number>[<unit>], where unit = b, k, m or g) (default \"20g\")",
				Default:     "20g",
				ForceNew:    true,
				Optional:    true,
			},
			"dns_domain": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The cluster dns domain name used in the kubernetes cluster (default \"cluster.local\")",
				Default:     "cluster.local",
				ForceNew:    true,
				Optional:    true,
			},
			"docker_env": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Environment variables to pass to the Docker daemon. (format: key=value)",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
				DefaultFunc: func() (interface{}, error) {
					return []string{}, nil
				},
			},
			"docker_opt": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Specify arbitrary flags to pass to the Docker daemon. (format: key=value)",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
				DefaultFunc: func() (interface{}, error) {
					return []string{}, nil
				},
			},
			"driver": &schema.Schema{
				Type:        schema.TypeString,
				Description: fmt.Sprintf("Driver is one of: %v (defaults to virtualbox)", driver.DisplaySupportedDrivers()),
				Default:     "virtualbox",
				ForceNew:    true,
				Optional:    true,
			},
			"extra_options": &schema.Schema{
				Type: schema.TypeString,
				Description: `A set of key=value pairs that describe configuration that may be passed to different components.
The key should be '.' separated, and the first part before the dot is the component to apply the configuration to.
Valid components are: kubelet, apiserver, controller-manager, etcd, proxy, scheduler.`,
				Default:  "",
				ForceNew: true,
				Optional: true,
			},
			"host_only_nic_type": &schema.Schema{
				Type:        schema.TypeString,
				Description: "NIC Type used for host only network. One of Am79C970A, Am79C973, 82540EM, 82543GC, 82545EM, or virtio (default: \"virtio\") (virtualbox driver only)",
				Default:     "virtio",
				ForceNew:    true,
				Optional:    true,
			},
			"hyperv_virtual_switch": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The hyperv virtual switch name. Defaults to first found. (hyperv driver only)",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"hyperv_use_external_switch": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "Whether to use external switch over Default Switch if virtual switch not explicitly specified. (hyperv driver only)",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"hyperv_external_adapter": &schema.Schema{
				Type:        schema.TypeString,
				Description: "External Adapter on which external switch will be created if no external switch is found. (hyperv driver only)",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"feature_gates": &schema.Schema{
				Type:        schema.TypeString,
				Description: "A set of key=value pairs that describe feature gates for alpha/experimental features.",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"host_only_cidr": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The CIDR to be used for the minikube VM (virtualbox driver only) (default \"192.168.99.1/24\")",
				Default:     "192.168.99.1/24",
				ForceNew:    true,
				Optional:    true,
			},
			"insecure_registry": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Insecure Docker registries to pass to the Docker daemon.  The default service CIDR range will automatically be added.",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
				DefaultFunc: func() (interface{}, error) {
					return []string{constants.DefaultServiceCIDR}, nil
				},
			},
			"iso_skip_checksum": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "Skip minikube ISO checksum verification on download (default: false)",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"iso_url": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Location of the minikube iso (default \"https://storage.googleapis.com/minikube/iso/minikube-v1.9.0.iso\")",
				Default:     "https://storage.googleapis.com/minikube/iso/minikube-v1.9.0.iso",
				ForceNew:    true,
				Optional:    true,
			},
			"keep_context": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "This will keep the existing kubectl context and will create a minikube context.",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"kubernetes_version": &schema.Schema{
				Type: schema.TypeString,
				Description: `The kubernetes version that the minikube VM will use (ex: v1.2.3)
 OR a URI which contains a localkube binary (ex: https://storage.googleapis.com/minikube/k8sReleases/v1.3.0/localkube-linux-amd64) (default "v1.16.8")`,
				Default:  "v1.16.8",
				ForceNew: true,
				Optional: true,
			},
			"kvm_gpu": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "Enable experimental NVIDIA GPU support in minikube",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"kvm_hidden": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "Hide the hypervisor signature from the guest in minikube (kvm2 driver only)",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"kvm_network": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The KVM network name. (kvm2 driver only) (default \"default\")",
				Default:     "default",
				ForceNew:    true,
				Optional:    true,
			},
			"kvm_qemu_uri": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The KVM QEMU connection URI. (kvm2 driver only) (default \"qemu:///system\")",
				Default:     "qemu:///system",
				ForceNew:    true,
				Optional:    true,
			},
			"memory": &schema.Schema{
				Type:        schema.TypeInt,
				Description: "Amount of RAM allocated to the minikube VM (default 2048)",
				Default:     2048,
				ForceNew:    true,
				Optional:    true,
			},
			//"mount": &schema.Schema{
			//	Type:        schema.TypeBool,
			//	Description: "This will start the mount daemon and automatically mount files into minikube",
			//	Default:     false,
			//	ForceNew:    true,
			//	Optional:    true,
			//},
			//"mount_string": &schema.Schema{
			//	Type:        schema.TypeString,
			//	Description: "The argument to pass the minikube mount command on start (default \"/Users:/minikube-host\")",
			//	Default:     "/Users:/minikube-host",
			//	ForceNew:    true,
			//	Optional:    true,
			//},
			"nat_nic_type": &schema.Schema{
				Type:        schema.TypeString,
				Description: "NIC Type used for NAT network. One of Am79C970A, Am79C973, 82540EM, 82543GC, 82545EM, or virtio (default: \"virtio\") (virtualbox driver only)",
				Default:     "virtio",
				ForceNew:    true,
				Optional:    true,
			},
			"network_plugin": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The name of the network plugin",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"pod_security_policy": &schema.Schema{
				Type:        schema.TypeBool,
				Description: "Enable PodSecurityPolicy (PSP) inside minikube (default: false)",
				Default:     false,
				ForceNew:    true,
				Optional:    true,
			},
			"registry_mirror": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Registry mirrors to pass to the Docker daemon",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
				DefaultFunc: func() (interface{}, error) {
					return []string{}, nil
				},
			},
			//"scheme": &schema.Schema{
			//	Type:        schema.TypeString,
			//	Description: "HTTP or HTTPS",
			//	Default:     "https",
			//	ForceNew:    true,
			//	Optional:    true,
			//},

			"client_certificate": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Base64 encoded public certificate used by clients to authenticate to the cluster endpoint.",
				Computed:    true,
			},
			"client_key": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Base64 encoded private key used by clients to authenticate to the cluster endpoint.",
				Computed:    true,
			},
			"cluster_ca_certificate": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Base64 encoded public certificate that is the root of trust for the cluster.",
				Computed:    true,
			},
			"endpoint": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Endpoint that can be used to reach API server",
				Computed:    true,
			},
		},
	}
}

func resourceMinikubeRead(d *schema.ResourceData, meta interface{}) error {
	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	profileName := d.Id()

	hostSt, err := machine.Status(api, profileName)
	if err != nil {
		log.Printf("Error getting host status for %s: %+v", profileName, err)
		return err
	}

	kubeletSt := state.None.String()
	apiserverSt := state.None.String()
	ks := state.None.String()

	clusterConfig, _, err := getClusterConfigFromResource(d)
	if err != nil {
		log.Printf("Error getting minikube cluster config from terraform resource: %+v", err)
		return err
	}

	nodeConfig := clusterConfig.Nodes[0]

	if hostSt == state.Running.String() {

		clusterBootstrapper, err := cluster.Bootstrapper(api, clusterBootstrapper, clusterConfig, nodeConfig)
		if err != nil {
			log.Printf("Error getting cluster bootstrapper: %+v", err)
			return err
		}
		kubeletSt, err = clusterBootstrapper.GetKubeletStatus()
		if err != nil {
			log.Printf("Error kubelet status: %+v", err)
			return err
		}

		ip, err := cluster.GetHostDriverIP(api, profileName)
		if err != nil {
			log.Printf("Error host driver ip status: %+v", err)
			return err
		}

		apiserverPort := nodeConfig.Port

		apiserverSt, err = clusterBootstrapper.GetAPIServerStatus(ip.String(), apiserverPort)
		returnCode := 0
		if err != nil {
			log.Printf("Error api-server status: %+v", err)
			return err
		} else if apiserverSt != state.Running.String() {
			returnCode |= clusterNotRunningStatusFlag
		}

		kstatus := kubeconfig.VerifyEndpoint(profileName, ip.String(), apiserverPort)
		//if err != nil {
		//	log.Printf("Error kubeconfig status: %v", err)
		//	return err
		//}
		if kstatus != nil {
			ks = "Correctly Configured: pointing to minikube-vm at " + ip.String()
		} else {
			ks = "Misconfigured: pointing to stale minikube-vm." +
				"\nTo fix the kubectl context, run minikube update-context"
		}
	}

	status := cmd.Status{
		Name:       profileName,
		Host:       hostSt,
		Kubelet:    kubeletSt,
		APIServer:  apiserverSt,
		Kubeconfig: ks,
		Worker:     false,
	}
	log.Printf("resourceMinikubeRead result: %+v", status)

	if kubeletSt == state.None.String() || apiserverSt == state.None.String() || ks == state.None.String() {
		// If the resource does not exist, inform Terraform. We want to immediately
		// return here to prevent further processing.
		d.SetId("")
		return nil
	}

	return nil
}

func resourceMinikubeCreate(d *schema.ResourceData, meta interface{}) error {
	// Load current profile cluster config from file
	//prof, err := cfg.LoadProfile(profile)
	////  && !os.IsNotExist(err)
	//
	//cc := cfg.ClusterConfig{}
	//
	//if err != nil {
	//	log.Printf("Error loading profile config: %v. Assume that we create cluster first time", err)
	//
	//	cc, err = getClusterConfigFromResource(d)
	//	if err != nil {
	//		log.Printf("Error getting DEFAULT cluster config from resource: %s\n", err)
	//		return err
	//	}
	//} else {
	//	cc = *prof.Config
	//}

	newClusterConfig, customConfig, err := getClusterConfigFromResource(d)
	if err != nil {
		log.Printf("Error getting cluster config from resource: %s\n", err)
		return err
	}

	profileName := newClusterConfig.Name

	existing, err := cfg.Load(profileName)
	if err != nil && !cfg.IsNotExist(err) {
		log.Printf("Error loading cluster config: %v", err)
		return err
	}

	skipISOChecksum := d.Get("iso_skip_checksum").(bool)

	nodeConfig := newClusterConfig.Nodes[0]

	//if cacheImages {
	//	go machine.CacheImagesForBootstrapper(clusterConfig.KubernetesConfig.ImageRepository,)
	//}

	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	//exists, err := api.Exists(profileName)
	//if err != nil {
	//	log.Printf("checking if machine exists: %s", err)
	//	return err
	//}

	log.Printf("Starting local Kubernetes %s cluster...\n", newClusterConfig.KubernetesConfig.KubernetesVersion)

	log.Printf("clusterConfig: %+v", newClusterConfig)
	log.Printf("nodeConfig: %+v", nodeConfig)

	log.Println("Starting VM...")

	validateSpecifiedDriver(existing, newClusterConfig.Driver)
	ds := selectDriver(existing, newClusterConfig)
	driverName := ds.Name
	log.Printf("selected driver: %s", driverName)
	validateDriver(ds, existing)
	//err = autoSetDriverOptions(cmd, driverName)
	//if err != nil {
	//	log.Printf("Error autoSetOptions : %v", err)
	//}

	if driver.IsVM(driverName) {
		urls := []string{newClusterConfig.MinikubeISO}
		urls = append(urls, download.DefaultISOURLs()...)

		url, err := download.ISO(urls, skipISOChecksum)
		if err != nil {
			log.Printf("Failed to cache ISO: %v", err)
			return err
		}
		newClusterConfig.MinikubeISO = url
	}

	log.Printf("Save current/new configuration to %s because we need it before VM start", profileName)
	if err := os.MkdirAll(cfg.ProfileFolderPath(profileName), 0777); err != nil {
		log.Printf("error creating profile directory '%s': %v", cfg.ProfileFolderPath(profileName), err)
		return err
	}

	if err := cfg.Write(profileName, &newClusterConfig); err != nil {
		log.Printf("Could not save current config to %s: %v", profileFilePath(profileName), err)
		return err
	}

	if customConfig.PSP {
		log.Printf("Preparing for enable PodSecurityPolicy in minikube...")
		if err := preparePSP(); err != nil {
			log.Printf("cannot prepare PSP YAML: %+v", err)
			return err
		}

		// add option to enable PSP
		e := cfg.ExtraOption{
			Component: "apiserver",
			Key:       "enable-admission-plugins",
			Value:     "PodSecurityPolicy",
		}

		es := &(newClusterConfig.KubernetesConfig.ExtraOptions)
		*es = append(*es, e)
	}

	host, _, err := machine.StartHost(api, newClusterConfig, nodeConfig)
	if err != nil {
		log.Printf("Error starting host: %v", err)
		return err
	}

	log.Println("Getting VM IP address...")
	ip, err := host.Driver.GetIP()
	if err != nil {
		log.Printf("Error getting VM IP address: %v", err)
		return err
	}

	// set (new) external IP of cluster node
	newClusterConfig.KubernetesConfig.NodeIP = ip
	newClusterConfig.Nodes[0].IP = ip
	// is this same thing?
	nodeConfig.IP = ip

	if existing != nil {
		oldKubernetesVersion, err := semver.Make(strings.TrimPrefix(existing.KubernetesConfig.KubernetesVersion, version.VersionPrefix))
		if err != nil {
			log.Printf("Error parsing version semver: %v", err)
		}

		newKubernetesVersion, err := semver.Make(strings.TrimPrefix(newClusterConfig.KubernetesConfig.KubernetesVersion, version.VersionPrefix))
		if err != nil {
			log.Printf("Error parsing version semver: %v", err)
		}

		// Check if it's an attempt to downgrade version. Avoid version downgrad.
		if newKubernetesVersion.LT(oldKubernetesVersion) {
			newClusterConfig.KubernetesConfig.KubernetesVersion = version.VersionPrefix + oldKubernetesVersion.String()
			log.Println("Kubernetes version downgrade is not supported. Using version:", newClusterConfig.KubernetesConfig.KubernetesVersion)
		}

		log.Printf("Merge old k8s cluster configuration with new one")
		newClusterConfig.KubernetesConfig.NodeIP = ip

		if err := mergo.Merge(&newClusterConfig, existing); err != nil {
			log.Printf("could not merge old and new profiles: %+v", err)
			return err
		}

		log.Printf("Save new configuration as profile '%s' after merge", profileName)
		if err := cfg.Write(profileName, &newClusterConfig); err != nil {
			log.Printf("could not save profile to %s after merge: %v", profileName, err)
			return err
		}
	}

	//cfg.SaveProfile(newClusterConfig.Name, &newClusterConfig)

	k8sBootstrapper, err := cluster.Bootstrapper(api, clusterBootstrapper, newClusterConfig, nodeConfig)
	if err != nil {
		log.Printf("Error getting cluster bootstrapper: %s", err)
		return err
	}

	log.Println("Update cluster configuration...")
	if err := k8sBootstrapper.UpdateCluster(newClusterConfig); err != nil {
		log.Printf("Error updating cluster: %v", err)
		return err
	}

	log.Println("Setting up certs...")
	if err := k8sBootstrapper.SetupCerts(newClusterConfig.KubernetesConfig, nodeConfig); err != nil {
		log.Printf("Error configuring authentication: %v", err)
		return err
	}

	log.Println("Connecting to cluster...")
	kubeHost, err := host.Driver.GetURL()
	if err != nil {
		log.Printf("Error connecting to cluster: %v", err)
	}
	kubeHost = strings.Replace(kubeHost, "tcp://", "https://", -1)
	kubeHost = strings.Replace(kubeHost, ":2376", ":"+strconv.Itoa(constants.APIServerPort), -1)

	log.Println("Setting up kubeconfig...")
	kcs := kubeconfig.Settings{
		ClusterName:          profileName,
		ClusterServerAddress: kubeHost,
		ClientCertificate:    localpath.ClientCert(profileName),
		CertificateAuthority: localpath.CACert(),
		ClientKey:            localpath.ClientKey(profileName),
		KeepContext:          newClusterConfig.KeepContext,
		//		EmbedCerts:           false,
	}
	kcs.SetPath(kubeconfig.PathFromEnv())

	// write the kubeconfig to the file system after everything required (like certs) are created by the bootstrapper
	if err := kubeconfig.Update(&kcs); err != nil {
		log.Printf("Failed to update kubeconfig file.")
		return err
	}

	log.Println("Starting cluster components...")

	if err := k8sBootstrapper.StartCluster(newClusterConfig); err != nil {
		log.Printf("Error (re)starting cluster: %v", err)
		return err
	}

	//// start 9p server mount
	//if mount {
	//	log.Printf("Setting up hostmount on %s...\n", mountString)
	//
	//	path := os.Args[0]
	//	mountDebugVal := 0
	//	mountCmd := exec.Command(path, "mount", fmt.Sprintf("--v=%d", mountDebugVal), mountString)
	//	mountCmd.Env = append(os.Environ(), constants.IsMinikubeChildProcess+"=true")
	//	err = mountCmd.Start()
	//	if err != nil {
	//		log.Printf("Error running command minikube mount %s", err)
	//		return err
	//	}
	//	err = ioutil.WriteFile(filepath.Join(constants.GetMinipath(), constants.MountProcessFileName), []byte(strconv.Itoa(mountCmd.Process.Pid)), 0644)
	//	if err != nil {
	//		log.Printf("Error writing mount process pid to file: %s", err)
	//		return err
	//	}
	//}

	if kcs.KeepContext {
		log.Printf("The local Kubernetes cluster has started. The kubectl context has not been altered, kubectl will require \"--context=%s\" to use the local Kubernetes cluster.\n",
			kcs.ClusterName)
	} else {
		log.Println("Kubectl is now configured to use the cluster.")
	}

	if newClusterConfig.Driver == "none" {
		log.Println(`===================
WARNING: IT IS RECOMMENDED NOT TO RUN THE NONE DRIVER ON PERSONAL WORKSTATIONS
	The 'none' driver will run an insecure kubernetes apiserver as root that may leave the host vulnerable to CSRF attacks
`)

		if os.Getenv("CHANGE_MINIKUBE_NONE_USER") == "" {
			log.Println(`When using the none driver, the kubectl config and credentials generated will be root owned and will appear in the root home directory.
You will need to move the files to the appropriate location and then set the correct permissions.  An example of this is below:

	sudo mv /root/.kube $HOME/.kube # this will write over any previous configuration
	sudo chown -R $USER $HOME/.kube
	sudo chgrp -R $USER $HOME/.kube

	sudo mv /root/.minikube $HOME/.minikube # this will write over any previous configuration
	sudo chown -R $USER $HOME/.minikube
	sudo chgrp -R $USER $HOME/.minikube

This can also be done automatically by setting the env var CHANGE_MINIKUBE_NONE_USER=true`)
		}
		if err := pkgutil.MaybeChownDirRecursiveToMinikubeUser(localpath.MiniPath()); err != nil {
			log.Printf("Error recursively changing ownership of directory %s: %s",
				localpath.MiniPath(), err)
			return err
		}
	}

	//log.Println("Loading cached images from config file.")
	//err = cmd.LoadCachedImagesInConfigFile()
	//if err != nil {
	//	log.Println("Unable to load cached images from config file.")
	//}

	d.SetId(profileName)

	clientCertificate, err := readFileAsBase64String(kcs.ClientCertificate)
	if err != nil {
		log.Printf("Failed to read client_certificate (%s)", kcs.ClientCertificate)
		return err
	}
	clientKey, err := readFileAsBase64String(kcs.ClientKey)
	if err != nil {
		log.Printf("Failed to read client_key (%s)", kcs.ClientKey)
		return err
	}
	clusterCACertificate, err := readFileAsBase64String(kcs.CertificateAuthority)
	if err != nil {
		log.Printf("Failed to read cluster_ca_certificate (%s)", kcs.CertificateAuthority)
		return err
	}

	d.Set("client_certificate", clientCertificate)
	d.Set("client_key", clientKey)
	d.Set("cluster_ca_certificate", clusterCACertificate)
	d.Set("endpoint", kubeHost)

	return resourceMinikubeRead(d, meta)
}

func getClusterConfigFromResource(d *schema.ResourceData) (cfg.ClusterConfig, CustomConfig, error) {
	customConfig := CustomConfig{
		PSP: false,
	}

	machineName := constants.DefaultClusterName

	apiserverName := d.Get("apiserver_name").(string)
	cacheImages := d.Get("cache_images").(bool)
	containerRuntime := d.Get("container_runtime").(string)
	cpus := d.Get("cpus").(int)
	disableDriverMounts := d.Get("disable_driver_mounts").(bool)
	diskSize := d.Get("disk_size").(string)
	dnsDomain := d.Get("dns_domain").(string)
	dockerEnv := d.Get("docker_env")
	dockerOpt := d.Get("docker_opt")
	//if !ok {
	//	dockerOpt = []string{}
	//}
	hostOnlyNicType := d.Get("host_only_nic_type").(string)

	hypervVirtualSwitch := d.Get("hyperv_virtual_switch").(string)
	hypervUseExternalSwitch := d.Get("hyperv_use_external_switch").(bool)
	hypervExternalAdapter := d.Get("hyperv_external_adapter").(string)

	featureGates := d.Get("feature_gates").(string)
	hostOnlyCIDR := d.Get("host_only_cidr").(string)
	insecureRegistry := d.Get("insecure_registry")
	isoURL := d.Get("iso_url").(string)
	keepContext := d.Get("keep_context").(bool)
	kubernetesVersion := d.Get("kubernetes_version").(string)
	kvmNetwork := d.Get("kvm_network").(string)
	kvmQemuURI := d.Get("kvm_qemu_uri").(string)
	kvmGPU := d.Get("kvm_gpu").(bool)
	kvmHidden := d.Get("kvm_hidden").(bool)
	memory := d.Get("memory").(int)
	natNicType := d.Get("nat_nic_type").(string)
	networkPlugin := d.Get("network_plugin").(string)
	psp := d.Get("pod_security_policy").(bool)
	registryMirror := d.Get("registry_mirror")
	vmDriver := d.Get("driver").(string)

	addons, ok := d.Get("addons").(map[string]bool)
	if !ok {
		addons = map[string]bool{}
	}

	extraOptionsStr := d.Get("extra_options").(string)

	extraOptions := cfg.ExtraOptionSlice{}
	if extraOptionsStr != "" {
		err := extraOptions.Set(extraOptionsStr)
		if err != nil {
			log.Printf("Error parsing extra options: %v", err)
			return cfg.ClusterConfig{}, customConfig, err
		}

		if strings.EqualFold(extraOptions.Get("enable-admission-plugins"), "PodSecurityPolicy") {
			log.Printf("For some reasons, 'enable-admission-plugins=PodSecurityPolicy' specified in extra_options cause Minikube bootstrap to hang, so you should use a 'pod_security_policy=true' instead if you want PSP.")
			return cfg.ClusterConfig{}, customConfig, errors.New("for some reasons, 'enable-admission-plugins=PodSecurityPolicy' specified in extra_options cause Minikube bootstrap to hang, so you should use a 'pod_security_policy=true' instead if you want PSP")
		}
	}
	// set PSP option
	customConfig.PSP = psp

	diskSizeMB, err := pkgutil.CalculateSizeInMB(diskSize)

	if err != nil {
		log.Printf("Error parsing disk size %s: %v", diskSize, err)
		return cfg.ClusterConfig{}, customConfig, err
	}

	if diskSizeMB < minimumDiskSizeInMB {
		err := fmt.Errorf("Disk Size %dMB (%s) is too small, the minimum disk size is %dMB", diskSizeMB, diskSize, minimumDiskSizeInMB)
		return cfg.ClusterConfig{}, customConfig, err
	}

	//log.Println("=================== Creating Minikube Cluster ==================")
	nodeConfig := cfg.Node{
		Name:              machineName,
		KubernetesVersion: kubernetesVersion,
		//ControlPlane:      true,
		//Worker:            true,
		//IP:                "127.0.0.1",
	}

	kubeConfig := cfg.KubernetesConfig{
		KubernetesVersion:      kubernetesVersion,
		ClusterName:            machineName,
		APIServerName:          apiserverName,
		DNSDomain:              dnsDomain,
		ContainerRuntime:       containerRuntime,
		NetworkPlugin:          networkPlugin,
		FeatureGates:           featureGates,
		ServiceCIDR:            constants.DefaultServiceCIDR,
		ExtraOptions:           extraOptions,
		ShouldLoadCachedImages: cacheImages,
		EnableDefaultCNI:       false,
		//NodeIP:                 "127.0.0.1",
		//NodePort:               0,
		NodeName: machineName,
	}

	log.Printf("kubeConfig: %v", kubeConfig)

	// https://pkg.go.dev/k8s.io/minikube/pkg/minikube/config?tab=doc#ClusterConfig
	conf := cfg.ClusterConfig{
		Name:                    machineName,
		KeepContext:             keepContext,
		MinikubeISO:             isoURL,
		Memory:                  memory,
		CPUs:                    cpus,
		DiskSize:                diskSizeMB,
		Driver:                  vmDriver,
		DockerEnv:               flattenStringList(dockerEnv),
		InsecureRegistry:        flattenStringList(insecureRegistry),
		RegistryMirror:          flattenStringList(registryMirror),
		HostOnlyCIDR:            hostOnlyCIDR, // Only used by the virtualbox driver
		HostOnlyNicType:         hostOnlyNicType,
		HypervVirtualSwitch:     hypervVirtualSwitch,
		HypervUseExternalSwitch: hypervUseExternalSwitch,
		HypervExternalAdapter:   hypervExternalAdapter,
		KVMNetwork:              kvmNetwork, // Only used by the KVM driver
		KVMQemuURI:              kvmQemuURI,
		KVMGPU:                  kvmGPU,
		KVMHidden:               kvmHidden,
		NatNicType:              natNicType,
		DockerOpt:               flattenStringList(dockerOpt), // Each entry is formatted as KEY=VALUE.
		DisableDriverMounts:     disableDriverMounts,          // Only used by virtualbox
		KubernetesConfig:        kubeConfig,
		Nodes:                   []cfg.Node{nodeConfig},
		Addons:                  addons,
	}

	log.Printf("clusterConfig: %v", conf)

	return conf, customConfig, nil
}

func readFileAsBase64String(path string) (string, error) {
	file, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}
	return b64.StdEncoding.EncodeToString(file), nil
}

func resourceMinikubeDelete(d *schema.ResourceData, _ interface{}) error {
	log.Println("Deleting local Kubernetes cluster...")

	config, _, err := getClusterConfigFromResource(d)
	if err != nil {
		log.Printf("Error getting cluster config: %s\n", err)
		return err
	}

	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	if err = machine.DeleteHost(api, config.Name); err != nil {
		log.Println("Errors occurred deleting machine: ", err)
		return err
	}
	fmt.Println("Machine deleted.")

	//if err := KillMountProcess(); err != nil {
	//	log.Println("Errors occurred deleting mount process: ", err)
	//}

	if err := cfg.DeleteProfile(profile); err != nil {
		log.Println("Error deleting machine profile config")
		return err
	}
	d.SetId("")
	return nil
}

func flattenStringList(in interface{}) []string {
	inlist := in.([]interface{})

	var out = make([]string, len(inlist))

	for i, v := range inlist {
		out[i] = v.(string)
	}
	return out
}

// all code from https://github.com/kubernetes/minikube/blob/master/cmd/minikube/cmd/start.go
func selectDriver(existing *cfg.ClusterConfig, new cfg.ClusterConfig) registry.DriverState {
	// Technically unrelated, but important to perform before detection
	driver.SetLibvirtURI(new.KVMQemuURI)

	// By default, the driver is whatever we used last time
	if existing != nil {
		old := hostDriver(existing)
		ds := driver.Status(old)
		log.Printf("Using the %s driver based on existing profile", ds.String())
		return ds
	}

	// Default to looking at the new driver parameter
	if d := new.Driver; d != "" {
		ds := driver.Status(d)
		if ds.Name == "" {
			log.Printf("The driver '%s' is not supported on %s", d, runtime.GOOS)
			return registry.DriverState{
				Name:      d,
				Priority:  0,
				State:     registry.State{Error: errors.New(fmt.Sprintf("The driver '%s' is not supported on %s", d, runtime.GOOS))},
				Rejection: fmt.Sprintf("The driver '%s' is not supported on %s", d, runtime.GOOS),
			}
		}
		log.Printf("Using the %s driver based on user configuration", ds.String())
		return ds
	}

	choices := driver.Choices(true)
	pick, alts, rejects := driver.Suggest(choices)
	if pick.Name == "" {
		log.Printf("Unable to pick a default driver. Here is what was considered, in preference order:")
		for _, r := range rejects {
			log.Printf("%s: %s", r.Name, r.Rejection)
		}
		log.Printf("Try specifying a 'driver' resource option manually")
		os.Exit(exit.Unavailable)
	}

	if len(alts) > 1 {
		altNames := []string{}
		for _, a := range alts {
			altNames = append(altNames, a.String())
		}
		log.Printf("Automatically selected the %s driver. Other choices: %s", pick.Name, strings.Join(altNames, ", "))
	} else {
		log.Printf("Automatically selected the %s driver", pick.String())
	}
	return pick
}

// hostDriver returns the actual driver used by a libmachine host, which can differ from our config
func hostDriver(existing *cfg.ClusterConfig) string {
	if existing == nil {
		return ""
	}
	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("hostDriver NewAPIClient: %v", err)
		return existing.Driver
	}

	cp, err := cfg.PrimaryControlPlane(existing)
	if err != nil {
		log.Printf("Unable to get control plane from existing config: %v", err)
		return existing.Driver
	}
	machineName := driver.MachineName(*existing, cp)
	h, err := api.Load(machineName)
	if err != nil {
		log.Printf("hostDriver api.Load: %v", err)
		return existing.Driver
	}

	return h.Driver.DriverName()
}

// validateSpecifiedDriver makes sure that if a user has passed in a driver
// it matches the existing cluster if there is one
func validateSpecifiedDriver(existing *cfg.ClusterConfig, requested string) error {
	if existing == nil {
		return nil
	}

	if requested == "" {
		return nil
	}

	old := hostDriver(existing)
	if requested == old {
		return nil
	}

	return errors.New(fmt.Sprintf("The existing minikube VM was created using the %s driver, and is incompatible with the %s driver.", old, requested))
}

// validateDriver validates that the selected driver appears sane, exits if not
func validateDriver(ds registry.DriverState, existing *cfg.ClusterConfig) {
	name := ds.Name
	log.Printf("validating driver %q against %+v", name, existing)
	if !driver.Supported(name) {
		exit.WithCodeT(exit.Unavailable, "The driver '{{.driver}}' is not supported on {{.os}}", out.V{"driver": name, "os": runtime.GOOS})
	}

	st := ds.State
	log.Printf("status for %s: %+v", name, st)

	if st.Error != nil {
		out.ErrLn("")

		out.WarningT("'{{.driver}}' driver reported an issue: {{.error}}", out.V{"driver": name, "error": st.Error})
		out.ErrT(out.Tip, "Suggestion: {{.fix}}", out.V{"fix": translate.T(st.Fix)})
		if st.Doc != "" {
			out.ErrT(out.Documentation, "Documentation: {{.url}}", out.V{"url": st.Doc})
		}
		out.ErrLn("")

		if !st.Installed {
			if existing != nil {
				if old := hostDriver(existing); name == old {
					exit.WithCodeT(exit.Unavailable, "{{.driver}} does not appear to be installed, but is specified by an existing profile. Please run 'minikube delete' or install {{.driver}}", out.V{"driver": name})
				}
			}
			exit.WithCodeT(exit.Unavailable, "{{.driver}} does not appear to be installed", out.V{"driver": name})
		}
	}
}

// profileFilePath returns path of profile config file
func profileFilePath(profile string, miniHome ...string) string {
	miniPath := localpath.MiniPath()
	if len(miniHome) > 0 {
		miniPath = miniHome[0]
	}

	return filepath.Join(miniPath, "profiles", profile, "config.json")
}

func preparePSP() error {
	var policiesContent bytes.Buffer
	opts := struct{}{}

	if err := PSPyml.Execute(&policiesContent, opts); err != nil {
		log.Printf("cannot template PSP: %+v", err)
		return err
	}

	addonsFolder := localpath.MakeMiniPath("files", "etc", "kubernetes", "addons")

	if err := os.MkdirAll(addonsFolder, 0755); err != nil {
		log.Printf("error creating minikube addons directory '%s': %v", addonsFolder, err)
		return err
	}

	addonsPath := []string{addonsFolder}
	addonsPath = append(addonsPath, "psp.yaml")
	policiesFilePath := filepath.Join(addonsPath...)

	return ioutil.WriteFile(policiesFilePath, policiesContent.Bytes(), 0644)
}
