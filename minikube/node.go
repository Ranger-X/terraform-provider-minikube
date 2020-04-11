package minikube

import (
	"context"
	"fmt"
	"github.com/blang/semver"
	"github.com/docker/machine/libmachine"
	"github.com/docker/machine/libmachine/host"
	"github.com/imdario/mergo"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
	"k8s.io/minikube/pkg/addons"
	"k8s.io/minikube/pkg/drivers/kic"
	"k8s.io/minikube/pkg/minikube/bootstrapper"
	"k8s.io/minikube/pkg/minikube/bootstrapper/bsutil/kverify"
	"k8s.io/minikube/pkg/minikube/bootstrapper/images"
	"k8s.io/minikube/pkg/minikube/cluster"
	"k8s.io/minikube/pkg/minikube/command"
	"k8s.io/minikube/pkg/minikube/config"
	"k8s.io/minikube/pkg/minikube/constants"
	"k8s.io/minikube/pkg/minikube/cruntime"
	"k8s.io/minikube/pkg/minikube/download"
	"k8s.io/minikube/pkg/minikube/driver"
	"k8s.io/minikube/pkg/minikube/exit"
	"k8s.io/minikube/pkg/minikube/image"
	"k8s.io/minikube/pkg/minikube/kubeconfig"
	"k8s.io/minikube/pkg/minikube/localpath"
	"k8s.io/minikube/pkg/minikube/machine"
	"k8s.io/minikube/pkg/minikube/node"
	"k8s.io/minikube/pkg/minikube/proxy"
	"k8s.io/minikube/pkg/util"
	"k8s.io/minikube/pkg/util/retry"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Start spins up a guest and starts the kubernetes node.
func Start(cc config.ClusterConfig, n config.Node, cu CustomConfig, existingAddons map[string]bool) (kcs *kubeconfig.Settings, host *host.Host, err error) {

	log.Printf("Starting control plane node %s in cluster %s", n.Name, cc.Name)

	var kicGroup errgroup.Group
	if driver.IsKIC(cc.Driver) {
		beginDownloadKicArtifacts(&kicGroup)
	}

	var cacheGroup errgroup.Group
	if !driver.BareMetal(cc.Driver) {
		beginCacheKubernetesImages(&cacheGroup, cc.KubernetesConfig.ImageRepository, n.KubernetesVersion, cc.KubernetesConfig.ContainerRuntime, cu)
	}

	// Abstraction leakage alert: startHost requires the config to be saved, to satistfy pkg/provision/buildroot.
	// Hence, saveConfig must be called before startHost, and again afterwards when we know the IP.
	if err := config.SaveProfile(cu.ProfileName, &cc); err != nil {
		log.Printf("failed to save config: %+v", err)
		return nil, nil, err
	}

	waitDownloadKicArtifacts(&kicGroup)

	mRunner, preExists, machineAPI, host, err := startMachine(&cc, &n)
	if err != nil {
		log.Printf("Could not startMachine: %+v", err)
		return nil, nil, err
	}

	defer machineAPI.Close()

	// wait for preloaded tarball to finish downloading before configuring runtimes
	waitCacheRequiredImages(&cacheGroup, cu)

	sv, err := util.ParseKubernetesVersion(n.KubernetesVersion)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to parse kubernetes version")
	}

	// configure the runtime (docker, containerd, crio)
	_, err = configureRuntimes(mRunner, cc.Driver, cc.KubernetesConfig, sv, cu)
	if err != nil {
		log.Printf("Could not configureRuntimes: %+v", err)
		return
	}

	log.Println("Getting VM IP address...")
	ip, err := host.Driver.GetIP()
	if err != nil {
		return nil, nil, fmt.Errorf("error getting VM IP address: %+v", err)
	}

	// set (new) external IP of cluster node
	cc.KubernetesConfig.NodeIP = ip
	cc.Nodes[0].IP = ip

	var bs bootstrapper.Bootstrapper

	// Must be written before bootstrap, otherwise health checks may flake due to stale IP
	kcs, err = setupKubeconfig(host, &cc, &n, cc.Name)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to setup kubeconfig")
	}

	// setup kubeadm (must come after setupKubeconfig)
	bs, err = setupKubeAdm(machineAPI, cc, n, cu)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to setup kubeadm")
	}

	err = bs.StartCluster(cc)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Failed to StartCluster")
	}

	// write the kubeconfig to the file system after everything required (like certs) are created by the bootstrapper
	if err := kubeconfig.Update(kcs); err != nil {
		return nil, nil, errors.Wrap(err, "Failed to update kubeconfig file.")
	}

	//configureMounts()

	if err := node.CacheAndLoadImagesInConfig(); err != nil {
		log.Printf("Unable to load cached images from config file.")
	}

	c, err := machine.CommandRunner(host)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get command runner: %+v", err)
	}

	if cu.PSP {
		log.Printf("Applying default Pod Security Policies...")
		// apply PSP manifest
		manifests := []string{fmt.Sprintf("/etc/kubernetes/addons/%s", pspFileName)}
		kubectlCmd := kubectlCommand(&cc, manifests, true)

		// Retry, because sometimes we race against an apiserver restart
		apply := func() error {
			_, err := c.RunCmd(kubectlCmd)
			if err != nil {
				log.Printf("kubectl apply failed, will retry: %+v", err)
			}
			return err
		}

		err = retry.Expo(apply, 1*time.Second, time.Second*30)
		if err != nil {
			log.Printf("Cannot apply PodSecurityPolicy manifest in the minikube (%+v). This might cause some trouble/errors. But continue", err)
		}
	}

	// enable addons AFTER PodSecurityPolicy was applied
	var mAddons map[string]bool
	if cu.InstallAddons {
		log.Printf("mAddons: %+v existingAddons: %+v", cc.Addons, existingAddons)
		mAddons = cc.Addons
		if existingAddons != nil {
			if err := mergo.Merge(&mAddons, existingAddons); err != nil {
				return nil, nil, fmt.Errorf("cannot merge old and new addons configuration: %+v", err)
			}
		}

		for addonName, enabled := range mAddons {
			log.Printf("Setting addons.%s=%s in profile %q", addonName, strconv.FormatBool(enabled), cu.ProfileName)
			err := addons.Set(addonName, strconv.FormatBool(enabled), cu.ProfileName)
			if err != nil {
				// Intentionally non-fatal
				log.Printf("Enabling addon '%s' returned an error: %+v", addonName, err)
			}
		}
	}

	// special ops for none , like change minikube directory.
	// multinode super doesn't work on the none driver
	if cc.Driver == driver.None && len(cc.Nodes) == 1 {
		if err = prepareNone(); err != nil {
			return nil, nil, errors.Wrap(err, "Failed to prepare to None")
		}
	}

	// Skip pre-existing, because we already waited for health
	if kverify.ShouldWait(cc.VerifyComponents) && !preExists {
		if err := bs.WaitForNode(cc, n, 6*time.Minute); err != nil {
			return nil, nil, errors.Wrap(err, "Wait for node become ready failed")
		}
	}

	return kcs, host, nil
}

// BeginCacheKubernetesImages caches images required for kubernetes version in the background
func beginCacheKubernetesImages(g *errgroup.Group, imageRepository string, k8sVersion string, cRuntime string, c CustomConfig) {
	if c.Preload && download.PreloadExists(k8sVersion, cRuntime) {
		log.Printf("Caching tarball of preloaded images")
		err := download.Preload(k8sVersion, cRuntime)
		if err == nil {
			log.Printf("Finished downloading the preloaded tar for %s on %s", k8sVersion, cRuntime)
			return // don't cache individual images if preload is successful.
		}
		log.Printf("Error downloading preloaded artifacts will continue without preload: %+v", err)
	}

	if !c.CacheImages {
		return
	}

	g.Go(func() error {
		return machine.CacheImagesForBootstrapper(imageRepository, k8sVersion, c.Bootstrapper)
	})
}

// BeginDownloadKicArtifacts downloads the kic image + preload tarball, returns true if preload is available
func beginDownloadKicArtifacts(g *errgroup.Group) {
	log.Printf("Beginning downloading kic artifacts")
	g.Go(func() error {
		log.Printf("Downloading %s to local daemon", kic.BaseImage)
		return image.WriteImageToDaemon(kic.BaseImage)
	})
}

// ConfigureRuntimes does what needs to happen to get a runtime going.
func configureRuntimes(runner cruntime.CommandRunner, drvName string, k8s config.KubernetesConfig, kv semver.Version, cu CustomConfig) (cr cruntime.Manager, err error) {
	co := cruntime.Config{
		Type:   k8s.ContainerRuntime,
		Runner: runner, ImageRepository: k8s.ImageRepository,
		KubernetesVersion: kv,
	}
	cr, err = cruntime.New(co)
	if err != nil {
		log.Printf("failed configureRuntime: %+v", err)
		return
	}

	disableOthers := true
	if driver.BareMetal(drvName) {
		disableOthers = false
	}

	// Preload is overly invasive for bare metal, and caching is not meaningful. KIC handled elsewhere.
	if driver.IsVM(drvName) {
		if err := cr.Preload(k8s); err != nil {
			switch err.(type) {
			case *cruntime.ErrISOFeature:
				log.Printf("Existing disk is missing new features (%+v). To upgrade, remove current minikube cluster and initialize it again", err)
			default:
				log.Printf("%s preload failed: %v, falling back to caching images", cr.Name(), err)
			}

			if err := machine.CacheImagesForBootstrapper(k8s.ImageRepository, k8s.KubernetesVersion, cu.Bootstrapper); err != nil {
				exit.WithError("Failed to cache images", err)
			}
		}
	}

	err = cr.Enable(disableOthers)
	if err != nil {
		log.Printf("Failed to enable container runtime: %+v", err)
		return
	}

	return cr, nil
}

// startHost starts a new minikube host using a VM or None
func startHost(api libmachine.API, cc config.ClusterConfig, n config.Node) (*host.Host, bool, error) {
	host, exists, err := machine.StartHost(api, cc, n)
	if err == nil {
		return host, exists, nil
	}
	log.Printf("StartHost failed, but will try again: %+v", err)

	// NOTE: People get very cranky if you delete their prexisting VM. Only delete new ones.
	if !exists {
		err := machine.DeleteHost(api, driver.MachineName(cc, n))
		if err != nil {
			log.Printf("delete host: %+v", err)
		}
	}

	// Try again, but just once to avoid making the logs overly confusing
	time.Sleep(5 * time.Second)

	host, exists, err = machine.StartHost(api, cc, n)
	if err == nil {
		return host, exists, nil
	}

	// Don't use host.Driver to avoid nil pointer deref
	drv := cc.Driver

	log.Printf(`Failed to start %s %s: %+v`, drv, driver.MachineType(drv), err)
	return host, exists, err
}

// validateNetwork tries to catch network problems as soon as possible
func validateNetwork(h *host.Host, r command.Runner) (string, error) {
	ip, err := h.Driver.GetIP()
	if err != nil {
		log.Printf("Unable to get VM IP address: %+v", err)
		return "", err
	}

	optSeen := false
	warnedOnce := false
	for _, k := range proxy.EnvVars {
		if v := os.Getenv(k); v != "" {
			if !optSeen {
				log.Printf("Found network options:")
				optSeen = true
			}
			log.Printf("%s=%s", k, v)
			ipExcluded := proxy.IsIPExcluded(ip) // Skip warning if minikube ip is already in NO_PROXY
			k = strings.ToUpper(k)               // for http_proxy & https_proxy
			if (k == "HTTP_PROXY" || k == "HTTPS_PROXY") && !ipExcluded && !warnedOnce {
				log.Printf("You appear to be using a proxy, but your NO_PROXY environment does not include the minikube IP (%s). Please see %s for more details", ip, "https://minikube.sigs.k8s.io/docs/reference/networking/proxy/")
				warnedOnce = true
			}
		}
	}

	if !driver.BareMetal(h.Driver.DriverName()) && !driver.IsKIC(h.Driver.DriverName()) {
		if err := trySSH(h, ip); err != nil {
			return "", err
		}
	}

	// Non-blocking
	go tryRegistry(r, h.Driver.DriverName())
	return ip, nil
}

func trySSH(h *host.Host, ip string) error {
	sshAddr := net.JoinHostPort(ip, "22")

	dial := func() (err error) {
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.Dial("tcp", sshAddr)
		if err != nil {
			log.Printf("Unable to verify SSH connectivity: %+v. Will retry...", err)
			return err
		}
		_ = conn.Close()
		return nil
	}

	if err := retry.Expo(dial, time.Second, 13*time.Second); err != nil {
		log.Printf(`minikube is unable to connect to the VM: %+v

	This is likely due to one of two reasons:

	- VPN or firewall interference
	- %s network configuration issue

	Suggested workarounds:

	- Disable your local VPN or firewall software
	- Configure your local VPN or firewall to allow access to %s
	- Restart or reinstall %s
	- Use an alternative --vm-driver
	- Use --force to override this connectivity check
	`, err, h.Driver.DriverName(), ip, h.Driver.DriverName())
		return err
	}

	return nil
}

// prepareNone prepares the user and host for the joy of the "none" driver
func prepareNone() error {
	log.Println("Configuring local host environment ...")

	log.Println("")
	log.Println("The 'none' driver is designed for experts who need to integrate with an existing VM")
	log.Println("Most users should use the newer 'docker' driver instead, which does not require root!")
	log.Println("For more information, see: https://minikube.sigs.k8s.io/docs/reference/drivers/none/")
	log.Println("")

	if os.Getenv("CHANGE_MINIKUBE_NONE_USER") == "" {
		home := os.Getenv("HOME")
		log.Printf("kubectl and minikube configuration will be stored in %s\n", home)
		log.Println("To use kubectl or minikube commands as your own user, you may need to relocate them. For example, to overwrite your own settings, run:")

		log.Println("")
		log.Printf("sudo mv %s/.kube %s/.minikube $HOME\n", home, home)
		log.Println("sudo chown -R $USER $HOME/.kube $HOME/.minikube")
		log.Println("")

		log.Println("This can also be done automatically by setting the env var CHANGE_MINIKUBE_NONE_USER=true")
	}

	if err := util.MaybeChownDirRecursiveToMinikubeUser(localpath.MiniPath()); err != nil {
		return fmt.Errorf("Failed to change permissions for %s: %+v", localpath.MiniPath(), err)
	}
	return nil
}

// tryRegistry tries to connect to the image repository
func tryRegistry(r command.Runner, driverName string) {
	// 2 second timeout. For best results, call tryRegistry in a non-blocking manner.
	opts := []string{"-sS", "-m", "2"}

	proxy := os.Getenv("HTTPS_PROXY")
	if proxy != "" && !strings.HasPrefix(proxy, "localhost") && !strings.HasPrefix(proxy, "127.0") {
		opts = append([]string{"-x", proxy}, opts...)
	}

	repo := images.DefaultKubernetesRepo

	opts = append(opts, fmt.Sprintf("https://%s/", repo))
	if rr, err := r.RunCmd(exec.Command("curl", opts...)); err != nil {
		log.Printf("%s failed: %+v", rr.Args, err)
		log.Printf("This %s is having trouble accessing https://%s", driver.MachineType(driverName), repo)
		log.Printf("To pull new external images, you may need to configure a proxy: https://minikube.sigs.k8s.io/docs/reference/networking/proxy/")
	}
}

func apiServerURL(h host.Host, cc config.ClusterConfig, n config.Node) (string, error) {
	hostname, _, port, err := driver.ControlPaneEndpoint(&cc, &n, h.DriverName)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("https://" + net.JoinHostPort(hostname, strconv.Itoa(port))), nil
}

// setupKubeAdm adds any requested files into the VM before Kubernetes is started
func setupKubeAdm(mAPI libmachine.API, cfg config.ClusterConfig, n config.Node, cu CustomConfig) (bs bootstrapper.Bootstrapper, err error) {
	bs, err = cluster.Bootstrapper(mAPI, cu.Bootstrapper, cfg, n)
	if err != nil {
		return nil, fmt.Errorf("failed to get bootstrapper: %+v", err)
	}
	for _, eo := range config.ExtraOptions {
		log.Printf("%s.%s=%s", eo.Component, eo.Key, eo.Value)
	}
	// Loads cached images, generates config files, download binaries
	// update cluster and set up certs in parallel
	errs, _ := errgroup.WithContext(context.Background())
	errs.Go(func() error {
		if err := bs.UpdateCluster(cfg); err != nil {
			return fmt.Errorf("failed to update cluster: %+v", err)
		}
		return nil
	})

	errs.Go(func() error {
		if err := bs.SetupCerts(cfg.KubernetesConfig, n); err != nil {
			return fmt.Errorf("failed to setup certs: %+v", err)
		}
		return nil
	})

	return bs, errs.Wait()
}

func setupKubeconfig(h *host.Host, cc *config.ClusterConfig, n *config.Node, clusterName string) (kcs *kubeconfig.Settings, err error) {
	addr, err := apiServerURL(*h, *cc, *n)
	if err != nil {
		log.Printf("Failed to get API Server URL: %+v", err)
		return
	}

	if cc.KubernetesConfig.APIServerName != constants.APIServerName {
		addr = strings.Replace(addr, n.IP, cc.KubernetesConfig.APIServerName, -1)
	}

	log.Printf("set APIServer addr to %s in %s", addr, kubeconfig.PathFromEnv())

	kcs = &kubeconfig.Settings{
		ClusterName:          clusterName,
		ClusterServerAddress: addr,
		ClientCertificate:    localpath.ClientCert(cc.Name),
		ClientKey:            localpath.ClientKey(cc.Name),
		CertificateAuthority: localpath.CACert(),
		KeepContext:          cc.KeepContext,
		EmbedCerts:           cc.EmbedCerts,
	}

	kcs.SetPath(kubeconfig.PathFromEnv())
	return kcs, nil
}

// StartMachine starts a VM
func startMachine(cfg *config.ClusterConfig, node *config.Node) (runner command.Runner, preExists bool, machineAPI libmachine.API, host *host.Host, err error) {
	m, err := machine.NewAPIClient()
	if err != nil {
		log.Printf("Failed to get machine client: %+v", err)
		return
	}
	host, preExists, err = startHost(m, *cfg, *node)
	if err != nil {
		log.Printf("Failed to startHost: %+v", err)
		return
	}

	runner, err = machine.CommandRunner(host)
	if err != nil {
		log.Printf("Failed to get command runner: %+v", err)
		return
	}

	ip, err := validateNetwork(host, runner)
	if err != nil {
		log.Printf("Failed to validate network: %+v", err)
		return
	}

	// Bypass proxy for minikube's vm host ip
	err = proxy.ExcludeIP(ip)
	if err != nil {
		log.Printf("Failed to set NO_PROXY Env. Please use `export NO_PROXY=$NO_PROXY,%s`.", ip)
	}

	// Save IP to config file for subsequent use
	node.IP = ip
	err = config.SaveNode(cfg, node)
	if err != nil {
		log.Printf("Failed to save node (again): %+v", err)
		return
	}

	return runner, preExists, m, host, nil
}

// WaitDownloadKicArtifacts blocks until the required artifacts for KIC are downloaded.
func waitDownloadKicArtifacts(g *errgroup.Group) {
	if err := g.Wait(); err != nil {
		log.Printf("Error downloading kic artifacts: %+v", err)
		return
	}
	log.Printf("Successfully downloaded all kic artifacts")
}

// WaitCacheRequiredImages blocks until the required images are all cached.
func waitCacheRequiredImages(g *errgroup.Group, config CustomConfig) {
	if !config.CacheImages {
		return
	}
	if err := g.Wait(); err != nil {
		log.Printf("Error caching images: %+v", err)
	}
}
