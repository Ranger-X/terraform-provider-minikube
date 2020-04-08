package minikube

import (
	b64 "encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/blang/semver"
	"github.com/docker/machine/libmachine/state"
	"github.com/hashicorp/terraform/helper/schema"
	"github.com/imdario/mergo"
	"github.com/spf13/viper"
	"k8s.io/minikube/cmd/minikube/cmd"
	"k8s.io/minikube/pkg/minikube/bootstrapper"
	"k8s.io/minikube/pkg/minikube/cluster"
	cfg "k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/minikube/constants"
	"k8s.io/minikube/pkg/minikube/driver"
	"k8s.io/minikube/pkg/minikube/kubeconfig"
	"k8s.io/minikube/pkg/minikube/localpath"
	"k8s.io/minikube/pkg/minikube/machine"
	pkgutil "k8s.io/minikube/pkg/util"
	"k8s.io/minikube/pkg/version"
)

const clusterNotRunningStatusFlag = 1 << 1

var (
	clusterBootstrapper string = bootstrapper.Kubeadm
	profile             string = "terraform_minikube" //constants.DefaultClusterName
	minimumDiskSizeInMB int    = 3000
)

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
			},
			"docker_opt": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Specify arbitrary flags to pass to the Docker daemon. (format: key=value)",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
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
				//Default: []string{"10.0.0.0/24"},
				ForceNew: true,
				Optional: true,
			},
			"iso_url": &schema.Schema{
				Type:        schema.TypeString,
				Description: "Location of the minikube iso (default \"https://storage.googleapis.com/minikube/iso/minikube-v1.9.2.iso\")",
				Default:     "https://storage.googleapis.com/minikube/iso/minikube-v1.9.2.iso",
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
			"kvm_network": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The KVM network name. (kvm2 driver only) (default \"default\")",
				Default:     "default",
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
			"network_plugin": &schema.Schema{
				Type:        schema.TypeString,
				Description: "The name of the network plugin",
				Default:     "",
				ForceNew:    true,
				Optional:    true,
			},
			"registry_mirror": &schema.Schema{
				Type:        schema.TypeList,
				Description: "Registry mirrors to pass to the Docker daemon",
				Elem:        &schema.Schema{Type: schema.TypeString},
				ForceNew:    true,
				Optional:    true,
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

	hostSt, err := machine.Status(api, profile)
	if err != nil {
		log.Printf("Error getting host status: %v", err)
		return err
	}

	kubeletSt := state.None.String()
	apiserverSt := state.None.String()
	ks := state.None.String()

	clusterConfig, err := getClusterConfigFromResource(d)
	if err != nil {
		log.Printf("Error getting minikube cluster config from terraform resource: %s", err)
		return err
	}

	nodeConfig := clusterConfig.Nodes[0]
	nodeName := nodeConfig.Name

	if hostSt == state.Running.String() {

		clusterBootstrapper, err := cluster.Bootstrapper(api, clusterBootstrapper, clusterConfig, nodeConfig)
		if err != nil {
			log.Printf("Error getting cluster bootstrapper: %s", err)
			return err
		}
		kubeletSt, err = clusterBootstrapper.GetKubeletStatus()
		if err != nil {
			log.Printf("Error kubelet status: %v", err)
			return err
		}

		ip, err := cluster.GetHostDriverIP(api, nodeName)
		if err != nil {
			log.Printf("Error host driver ip status: %v", err)
			return err
		}

		apiserverPort := nodeConfig.Port

		apiserverSt, err = clusterBootstrapper.GetAPIServerStatus(ip.String(), apiserverPort)
		returnCode := 0
		if err != nil {
			log.Printf("Error api-server status: %v", err)
			return err
		} else if apiserverSt != state.Running.String() {
			returnCode |= clusterNotRunningStatusFlag
		}

		kstatus := kubeconfig.VerifyEndpoint(profile, ip.String(), apiserverPort)
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
		Host:       hostSt,
		Kubelet:    kubeletSt,
		APIServer:  apiserverSt,
		Kubeconfig: ks,
	}
	log.Printf("Result: %v", status)

	return nil
}

func resourceMinikubeCreate(d *schema.ResourceData, meta interface{}) error {
	// Load current profile cluster config from file
	prof, err := cfg.LoadProfile(profile)
	//  && !os.IsNotExist(err)

	cc := cfg.ClusterConfig{}

	if err != nil {
		log.Printf("Error loading profile config: %v. Assume that we create cluster first time", err)

		cc, err = getClusterConfigFromResource(d)
		if err != nil {
			log.Printf("Error getting DEFAULT cluster config from resource: %s\n", err)
			return err
		}
	} else {
		cc = *prof.Config
	}

	nodeConfig := cc.Nodes[0]

	newClusterConfig, err := getClusterConfigFromResource(d)
	if err != nil {
		log.Printf("Error getting cluster config from resource: %s\n", err)
		return err
	}

	//if cacheImages {
	//	go machine.CacheImagesForBootstrapper(clusterConfig.KubernetesConfig.ImageRepository,)
	//}

	api, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Error getting client: %s\n", err)
		return err
	}
	defer api.Close()

	exists, err := api.Exists(newClusterConfig.Name)
	if err != nil {
		log.Printf("checking if machine exists: %s", err)
		return err
	}

	//if err := saveConfig(interimConfig); err != nil {
	//	log.Printf("Error saving interim profile cluster configuration: %v", err)
	//}

	log.Printf("Starting local Kubernetes %s cluster...\n", newClusterConfig.KubernetesConfig.KubernetesVersion)
	log.Println("Starting VM...")

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

	oldKubernetesVersion, err := semver.Make(strings.TrimPrefix(cc.KubernetesConfig.KubernetesVersion, version.VersionPrefix))
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
	cc.KubernetesConfig.NodeIP = ip
	mergo.Merge(&newClusterConfig, cc)

	log.Printf("Save new configuration to %s profile", profile)
	cfg.SaveProfile(profile, &newClusterConfig)

	k8sBootstrapper, err := cluster.Bootstrapper(api, clusterBootstrapper, newClusterConfig, nodeConfig)
	if err != nil {
		log.Printf("Error getting cluster bootstrapper: %s", err)
		return err
	}

	log.Println("Moving files into cluster...")
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
		ClusterName:          newClusterConfig.Name,
		ClusterServerAddress: kubeHost,
		ClientCertificate:    localpath.ClientCert(newClusterConfig.Name),
		CertificateAuthority: localpath.CACert(),
		ClientKey:            localpath.ClientKey(newClusterConfig.Name),
		KeepContext:          newClusterConfig.KeepContext,
		//		EmbedCerts:           false,
	}

	// write the kubeconfig to the file system after everything required (like certs) are created by the bootstrapper
	if err := kubeconfig.Update(&kcs); err != nil {
		log.Printf("Failed to update kubeconfig file.")
		return err
	}

	log.Println("Starting cluster components...")

	if !exists {
		if err := k8sBootstrapper.StartCluster(newClusterConfig); err != nil {
			log.Printf("Error starting cluster: %v", err)
			return err
		}
	} else {
		log.Printf("Could not restart cluster. Not implemented yet :-(")
		return errors.New("could not restart cluster. Not implemented yet")
		//if err := k8sBootstrapper.RestartCluster(kubernetesConfig); err != nil {
		//	log.Printf("Error restarting cluster: %v", err)
		//	return err
		//}
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

	d.SetId(nodeConfig.Name)

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
	return err
}

func getClusterConfigFromResource(d *schema.ResourceData) (cfg.ClusterConfig, error) {
	machineName := constants.DefaultClusterName
	apiserverName := d.Get("apiserver_name").(string)
	cacheImages := d.Get("cache_images").(bool)
	containerRuntime := d.Get("container_runtime").(string)
	cpus := d.Get("cpus").(int)
	disableDriverMounts := d.Get("disable_driver_mounts").(bool)
	diskSize := d.Get("disk_size").(string)
	dnsDomain := d.Get("dns_domain").(string)
	dockerEnv, ok := d.GetOk("docker_env")

	if !ok {
		dockerEnv = []string{}
	}

	dockerOpt, ok := d.GetOk("docker_opt")
	if !ok {
		dockerOpt = []string{}
	}

	hypervVirtualSwitch := d.Get("hyperv_virtual_switch").(string)
	hypervUseExternalSwitch := d.Get("hyperv_use_external_switch").(bool)
	hypervExternalAdapter := d.Get("hyperv_external_adapter").(string)

	featureGates := d.Get("feature_gates").(string)
	hostOnlyCIDR := d.Get("host_only_cidr").(string)
	insecureRegistry, ok := d.GetOk("insecure_registry")
	if !ok {
		insecureRegistry = []string{constants.DefaultServiceCIDR}
	}
	isoURL := d.Get("iso_url").(string)
	keepContext := d.Get("keep_context").(bool)
	kubernetesVersion := d.Get("kubernetes_version").(string)
	kvmNetwork := d.Get("kvm_network").(string)
	memory := d.Get("memory").(int)
	networkPlugin := d.Get("network_plugin").(string)
	registryMirror, ok := d.GetOk("registry_mirror")
	if !ok {
		registryMirror = []string{}
	}
	vmDriver := d.Get("driver").(string)

	addons, ok := d.Get("addons").(map[string]bool)
	if !ok {
		addons = map[string]bool{}
	}

	extraOptionsStr := d.Get("extra_options").(string)

	extraOptions := cfg.ExtraOptionSlice{}
	err := extraOptions.Set(extraOptionsStr)
	if err != nil {
		log.Printf("Error parsing extra options: %v", err)
		return cfg.ClusterConfig{}, err
	}

	diskSizeMB, err := pkgutil.CalculateSizeInMB(viper.GetString(diskSize))

	if err != nil {
		log.Printf("Error parsing disk size: %v", err)
		return cfg.ClusterConfig{}, err
	}

	if diskSizeMB < minimumDiskSizeInMB {
		err := fmt.Errorf("Disk Size %dMB (%s) is too small, the minimum disk size is %dMB", diskSizeMB, diskSize, minimumDiskSizeInMB)
		return cfg.ClusterConfig{}, err
	}

	flag.Parse()
	//log.Println("=================== Creating Minikube Cluster ==================")
	nodeConfig := cfg.Node{
		Name:              machineName,
		KubernetesVersion: kubernetesVersion,
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
		//NodeIP:                 ip,
		//NodePort:               0,
		NodeName: machineName,
	}

	// https://pkg.go.dev/k8s.io/minikube/pkg/minikube/config?tab=doc#ClusterConfig
	config := cfg.ClusterConfig{
		Name:                    machineName,
		KeepContext:             keepContext,
		MinikubeISO:             isoURL,
		Memory:                  memory,
		CPUs:                    cpus,
		DiskSize:                diskSizeMB,
		Driver:                  vmDriver,
		DockerEnv:               dockerEnv.([]string),
		InsecureRegistry:        insecureRegistry.([]string),
		RegistryMirror:          registryMirror.([]string),
		HostOnlyCIDR:            hostOnlyCIDR, // Only used by the virtualbox driver
		HypervVirtualSwitch:     hypervVirtualSwitch,
		HypervUseExternalSwitch: hypervUseExternalSwitch,
		HypervExternalAdapter:   hypervExternalAdapter,
		KVMNetwork:              kvmNetwork,           // Only used by the KVM driver
		DockerOpt:               dockerOpt.([]string), // Each entry is formatted as KEY=VALUE.
		DisableDriverMounts:     disableDriverMounts,  // Only used by virtualbox
		KubernetesConfig:        kubeConfig,
		Nodes:                   []cfg.Node{nodeConfig},
		Addons:                  addons,
	}

	return config, nil
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

	config, err := getClusterConfigFromResource(d)
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

	if err = machine.DeleteHost(api, config.Nodes[0].Name); err != nil {
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

//func loadConfigFromFile(profile string) (cfg.Config, error) {
//	var cc cfg.Config
//
//	profileConfigFile := constants.GetProfileFile(profile)
//
//	if _, err := os.Stat(profileConfigFile); os.IsNotExist(err) {
//		return cc, err
//	}
//
//	data, err := ioutil.ReadFile(profileConfigFile)
//	if err != nil {
//		return cc, err
//	}
//
//	if err := json.Unmarshal(data, &cc); err != nil {
//		return cc, err
//	}
//	return cc, nil
//}
//
//// saveConfig saves profile cluster configuration in
//// $MINIKUBE_HOME/profiles/<profilename>/config.json
//func saveConfig(clusterConfig cfg.Config) error {
//	data, err := json.MarshalIndent(clusterConfig, "", "    ")
//	if err != nil {
//		return err
//	}
//
//	profileConfigFile := constants.GetProfileFile(profile)
//
//	if err := os.MkdirAll(filepath.Dir(profileConfigFile), 0700); err != nil {
//		return err
//	}
//
//	if err := saveConfigToFile(data, profileConfigFile); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func saveConfigToFile(data []byte, file string) error {
//	if _, err := os.Stat(file); os.IsNotExist(err) {
//		return ioutil.WriteFile(file, data, 0600)
//	}
//
//	tmpfi, err := ioutil.TempFile(filepath.Dir(file), "config.json.tmp")
//	if err != nil {
//		return err
//	}
//	defer os.Remove(tmpfi.Name())
//
//	if err = ioutil.WriteFile(tmpfi.Name(), data, 0600); err != nil {
//		return err
//	}
//
//	if err = tmpfi.Close(); err != nil {
//		return err
//	}
//
//	if err = os.Remove(file); err != nil {
//		return err
//	}
//
//	if err = os.Rename(tmpfi.Name(), file); err != nil {
//		return err
//	}
//	return nil
//}
