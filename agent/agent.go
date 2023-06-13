package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
	"reflect"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/agent/pipe"
	"github.com/neuvector/neuvector/agent/probe"
	"github.com/neuvector/neuvector/agent/resource"
	"github.com/neuvector/neuvector/agent/workerlet"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/container"
	"github.com/neuvector/neuvector/share/fsmon"
	"github.com/neuvector/neuvector/share/global"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const goroutineStackSize = 1024 * 1024

var containerTaskExitChan chan interface{} = make(chan interface{}, 1)
var errRestartChan chan interface{} = make(chan interface{}, 1)
var restartChan chan interface{} = make(chan interface{}, 1)
var monitorExitChan chan interface{} = make(chan interface{}, 1)

var Host share.CLUSHost = share.CLUSHost{
	Platform: share.PlatformDocker,
	Network:  share.NetworkDefault,
}
var Agent, parentAgent share.CLUSAgent
var agentEnv AgentEnvInfo

var evqueue cluster.ObjectQueueInterface
var messenger cluster.MessengerInterface
var agentTimerWheel *utils.TimerWheel
var prober *probe.Probe
var bench *Bench
var grpcServer *cluster.GRPCServer
var scanUtil *scanUtils.ScanUtil
var fileWatcher *fsmon.FileWatch

var connLog *log.Logger = log.New()
var nvSvcPort, nvSvcBrPort string
var driver string
var exitingFlag int32
var exitingTaskFlag int32

var walkerTask *workerlet.Tasker

func shouldExit() bool {  //在程序运行期间检查是否应该推出程序
	return (atomic.LoadInt32(&exitingFlag) != 0)
}

func assert(err error) {  //用于检查某个操作是否成功，并在操作失败时输出相应的错误信息并终止程序
	if err != nil {
		log.Fatal(err)
	}
}

func isAgentContainer(id string) bool {  //用于检查指定的容器 ID 是否与当前 Agent 容器或其父级 Agent 容器的 ID 匹配。
	return id == Agent.ID || id == parentAgent.ID
}

func getHostIPs() {  //用于获取主机的 IP 地址以及相关信息。
	addrs := getHostAddrs()
	Host.Ifaces, gInfo.hostIPs, gInfo.jumboFrameMTU, gInfo.ciliumCNI = parseHostAddrs(addrs, Host.Platform, Host.Network)  //解析主机信息
	if tun := global.ORCH.GetHostTunnelIP(addrs); tun != nil {
		Host.TunnelIP = tun
	}

	if global.ORCH.ConsiderHostsAsInternal() {
		addHostSubnets(Host.Ifaces, gInfo.localSubnetMap)
	}
	mergeLocalSubnets(gInfo.internalSubnets)
}

func taskReexamHostIntf() { //用于重新检查主机的网络接口信息并更新对应的全局变量
	log.Debug()
	oldIfaces := Host.Ifaces
	oldTunnelIP := Host.TunnelIP
	getHostIPs()
	if reflect.DeepEqual(oldIfaces, Host.Ifaces) != true ||
	reflect.DeepEqual(oldTunnelIP, Host.TunnelIP) != true {
		putHostIfInfo()
	}
}

//用于获取本地节点的信息。
//该函数的作用是获取本地节点的基本信息和网络环境信息，并将其存储到全局变量中以供 NeuVector Agent 使用。在容器环境下，该函数还会获取容器的设备信息和 cgroup 信息，以便更好地监控容器。
func getLocalInfo(selfID string, pid2ID map[int]string) error {
	host, err := global.RT.GetHost()  //获取主机的基本信息，并将其存储到全局变量 Host 中。
	if err != nil {
		return err
	}
	Host = *host
	Host.CgroupVersion = global.SYS.GetCgroupVersion()  //获取系统的 cgroup 版本，并将其保存到 Host.CgroupVersion 中。

	getHostIPs()  //获取主机的网络接口信息和 IP 地址，并将其存储到全局变量中。

	if networks, err := global.RT.ListNetworks(); err != nil {  //获取容器网络信息，并将其存储到全局变量 gInfo.networks 中。
		log.WithFields(log.Fields{"error": err}).Error("Error reading container networks")
	} else {
		gInfo.networks = networks
	}

	agentEnv.startsAt = time.Now().UTC()
	if agentEnv.runInContainer {  //如果当前运行在容器中，则调用 global.RT.GetDevice() 函数获取容器的设备信息，并将其存储到全局变量 Agent.CLUSDevice 和 parentAgent.CLUSDevice 中。
		dev, meta, err := global.RT.GetDevice(selfID)
		if err != nil {
			return err
		}
		Agent.CLUSDevice = *dev

		_, parent := global.RT.GetParent(meta, pid2ID)
		if parent != "" { 
			dev, _, err := global.RT.GetDevice(parent)
			if err != nil {
				return err
			}
			parentAgent.CLUSDevice = *dev
			if parentAgent.PidMode == "host" {   //如果容器是以 PID 模式运行的，则将 Agent.PidMode 设置为 "host"。
				Agent.PidMode = "host"
			}
		}
	} else {  //如果当前未运行在容器中，则将 Agent.ID 设为主机 ID，Agent.Pid 设为当前进程 ID，Agent.NetworkMode 和 Agent.PidMode 均设置为 "host"。并将 Agent.SelfHostname、Agent.Ifaces、Agent.HostName、Agent.HostID 和 Agent.Ver 分别设置为主机名、网络接口信息、主机名、主机 ID 和 NeuVector 版本。
		Agent.ID = Host.ID
		Agent.Pid = os.Getpid()
		Agent.NetworkMode = "host"
		Agent.PidMode = "host"
		Agent.SelfHostname = Host.Name
		Agent.Ifaces = Host.Ifaces
	}
	Agent.HostName = Host.Name
	Agent.HostID = Host.ID
	Agent.Ver = Version
//调用 global.SYS.GetContainerCgroupPath() 函数获取容器的 cgroup 信息，并将其存储到全局变量中。
	agentEnv.cgroupMemory, _ = global.SYS.GetContainerCgroupPath(0, "memory")
	agentEnv.cgroupCPUAcct, _ = global.SYS.GetContainerCgroupPath(0, "cpuacct")
	return nil
}

// Sort existing containers, move containers share network ns to other containers to the front.
// Only need to consider containers in the set, not those already exist.
//排序的方式是将共享网络命名空间的容器放到数组的前面，未共享网络命名空间的容器放到数组的后面。
//总的来说，该函数的作用是对一组容器按照网络模式进行排序，以便 NeuVector Agent 更好地监控和管理这些容器。
func sortContainerByNetMode(ids utils.Set) []*container.ContainerMetaExtra {
	sorted := make([]*container.ContainerMetaExtra, 0, ids.Cardinality())
	for id := range ids.Iter() {
		if info, err := global.RT.GetContainer(id.(string)); err == nil {
			sorted = append(sorted, info)
		}
	}

	return container.SortContainers(sorted)
}

// Sort existing containers, move containers share network ns to other containers to the front.
// Only for Container Start from Probe channel
//用于将容器按照网络模式排序。与 sortContainerByNetMode() 函数不同的是，该函数只对从 Probe 通道启动的容器进行排序。
/*
Probe 通道是 NeuVector Agent 用于从多个来源获取容器信息的一种机制。具体来说，当 NeuVector Agent 启动时，它会通过不同的方式（如 Docker API、Kubernetes API 等）获取当前主机上运行的容器信息并存储到本地缓存中。但由于容器可能在 Agent 启动之后才启动或被创建，所以仅依靠缓存中的信息可能无法完整地了解容器的状态和配置。
为了解决这个问题，NeuVector Agent 引入了 Probe 通道机制。当某个容器启动时，Agent 会通知 Probe 服务，并告知 Probe 服务需要对该容器进行监控。然后 Probe 服务会向 Agent 提供容器的基本信息和事件信息等，以便 Agent 更好地监控和管理容器。
例如，在 Kubernetes 集群中，当某个 Pod 中的容器启动时，NeuVector Agent 可以通过 Kubernetes API Server 接收到事件通知，并将其转发给 Probe 服务。然后 Probe 服务就可以根据事件通知来获取该容器的基本信息，并将其提供给 Agent 进行处理。这样就可以确保 Agent 可以实时地获取容器的最新状态，从而更好地保护容器安全。
*/
func sortProbeContainerByNetMode(starts utils.Set) []*container.ContainerMetaExtra {
	sorted := make([]*container.ContainerMetaExtra, 0, starts.Cardinality())
	for start := range starts.Iter() {
		s := start.(*share.ProbeContainerStart)
		if info, err := global.RT.GetContainer(s.Id); err == nil {
			if info.Running && info.Pid == 0 { // cri-o: fault-tolerent for http channel errors
				info.Pid = s.RootPid_alt
				log.WithFields(log.Fields{"id": s.Id, "rootPid": info.Pid}).Debug("PROC: Update")
			}
			sorted = append(sorted, info)
		}
	}

	return container.SortContainers(sorted)
}

// Enforcer cannot run together with enforcer.
// With SDN, enforcer can run together with controller; otherwise, port conflict will prevent them from running.
//用于检查容器之间的互斥性关系，确保不会同时运行多个 Enforcer 容器。
func checkAntiAffinity(containers []*container.ContainerMeta, skips ...string) error {
	skipSet := utils.NewSet()
	for _, skip := range skips {
		skipSet.Add(skip)
	}

	for _, c := range containers {
		if skipSet.Contains(c.ID) {
			continue
		}

		if v, ok := c.Labels[share.NeuVectorLabelRole]; ok {
			if strings.Contains(v, share.NeuVectorRoleEnforcer) {
				return fmt.Errorf("Must not run with another enforcer")
			}
		}
	}
	return nil
}

//用于重新运行 Kubernetes 安全扫描工具 Kube-bench。
// cmd 参数指定要执行的命令，例如 "master" 或 "node" 等；
// cmdRemap 参数指定命令重映射表，用于将一些命令重定向到其他的命令，以便满足特定的需求。
func cbRerunKube(cmd, cmdRemap string) {
	if Host.CapKubeBench {
		bench.RerunKube(cmd, cmdRemap, false)
	}
}

//该函数的作用是确保容器任务队列已经完全退出，并且容器端口已经恢复正常。
func waitContainerTaskExit() {
	// Wait for container task gorouting exiting and container ports' are restored.
	// If clean-up doesn't star, it's possible that container task queue get stuck.
	// In that case, call clean-up function directly and move forward. If the clean-up
	// already started, keep waiting.
	for {  //无限循环
		select {
		case <-containerTaskExitChan:  //如果容器任务队列已退出，则直接返回。
			return
		case <-time.After(time.Second * 4):  //否则，等待 4 秒钟。如果在等待期间发现容器任务队列已经完全退出，那么调用 containerTaskExit() 函数，并立即返回。
			if atomic.LoadInt32(&exitingTaskFlag) == 0 {  //检查一个名为 exitingTaskFlag 的原子标志变量，以判断任务队列是否仍在运行中
				containerTaskExit()
				return
			}
		}
	}
}

//用于将当前 Enforcer 进程中所有 goroutine 的栈信息输出到日志中。
//该函数的作用是帮助开发人员在调试和排查问题时，快速定位和诊断 Enforcer 进程中可能存在的问题，并提供相应的解决方案。
func dumpGoroutineStack() {
	log.Info("Enforcer goroutine stack")
	buf := make([]byte, goroutineStackSize)
	bytes := runtime.Stack(buf, true)
	if bytes > 0 {
		log.Printf("%s", buf[:bytes])
	}
}

func main() {
	var joinAddr, advAddr, bindAddr string
	var err error

	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&utils.LogFormatter{Module: "AGT"})

	connLog.Out = os.Stdout
	connLog.Level = log.InfoLevel
	connLog.Formatter = &utils.LogFormatter{Module: "AGT"}

	log.WithFields(log.Fields{"version": Version}).Info("START")

	// log_file, log_err := os.OpenFile(LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	// if log_err == nil {
	//	  log.SetOutput(log_file)
	//    defer log_file.close()
	// }

	//这段代码使用了Go标准库中的flag包，定义了一系列命令行标志。
	withCtlr := flag.Bool("c", false, "Coexist controller and ranger")
	debug := flag.Bool("d", false, "Enable control path debug")
	debug_level := flag.String("v", "", "debug level")
	join := flag.String("j", "", "Cluster join address")
	adv := flag.String("a", "", "Cluster advertise address")
	bind := flag.String("b", "", "Cluster bind address")
	rtSock := flag.String("u", "", "Container socket URL")
	lanPort := flag.Uint("lan_port", 0, "Cluster Serf LAN port")
	grpcPort := flag.Uint("grpc_port", 0, "Cluster GRPC port")
	pipeType := flag.String("p", "", "Pipe driver")
	cnet_type := flag.String("n", "", "Container Network type")
	skip_nvProtect := flag.Bool("s", false, "Skip NV Protect")
	show_monitor_trace := flag.Bool("m", false, "Show process/file monitor traces")
	disable_kv_congest_ctl := flag.Bool("no_kvc", false, "disable kv congestion control")
	disable_scan_secrets := flag.Bool("no_scrt", false, "disable secret scans")
	disable_auto_benchmark := flag.Bool("no_auto_benchmark", false, "disable auto benchmark")
	disable_system_protection := flag.Bool("no_sys_protect", false, "disable system protections")
	flag.Parse()

	//该代码块用于根据命令行参数来调整日志和调试设置，例如根据debug标志判断是否需要启用调试模式，并根据debug_level标志添加其他调试信息等。
	if *debug {
		log.SetLevel(log.DebugLevel)
		gInfo.agentConfig.Debug = []string{"ctrl"}
	}

	if *debug_level != "" {
		levels := utils.NewSetFromSliceKind(append(gInfo.agentConfig.Debug, strings.Split(*debug_level, " ")...))
		if !*debug && levels.Contains("ctrl") {
			levels.Remove("ctrl")
		}
		gInfo.agentConfig.Debug = levels.ToStringSlice()
	}

	//首先将agentEnv.kvCongestCtrl属性默认值设为true，表示开启KV拥塞控制。然后，如果命令行标志disable_kv_congest_ctl被设置，则将日志输出一条信息："KV congestion control is disabled"，并将agentEnv.kvCongestCtrl属性的值设置为false，即关闭该功能。
	//KV拥塞控制通常是指分布式存储系统中对Key-Value（KV）数据访问的流量进行控制和调整，目的是避免因过多的并发访问或频繁的读写操作导致系统性能下降或崩溃。
	agentEnv.kvCongestCtrl = true
	if *disable_kv_congest_ctl {
		log.Info("KV congestion control is disabled")
		agentEnv.kvCongestCtrl = false
	}

	//将agentEnv.scanSecrets属性的默认值设为true，表示开启容器中秘密信息的扫描。如果命令行标志disable_scan_secrets被设置，则将日志输出一条信息："Scanning secrets on containers is disabled"，并将agentEnv.scanSecrets属性的值设置为false，即关闭该功能。
	agentEnv.scanSecrets = true
	if *disable_scan_secrets {
		log.Info("Scanning secrets on containers is disabled")
		agentEnv.scanSecrets = false
	}

	//将agentEnv.autoBenchmark属性的默认值设为true，表示开启自动基准测试功能。如果命令行标志disable_auto_benchmark被设置，则将日志输出一条信息："Auto benchmark is disabled"，并将agentEnv.autoBenchmark属性的值设置为false，即关闭该功能。
	agentEnv.autoBenchmark = true
	if *disable_auto_benchmark {
		log.Info("Auto benchmark is disabled")
		agentEnv.autoBenchmark = false
	}

	//将agentEnv.systemProfiles属性默认值设为true，表示开启系统保护功能。然后，如果命令行标志disable_system_protection被设置，则将日志输出一条信息："System protection is disabled (process/file profiles)"，并将agentEnv.systemProfiles属性的值设置为false，即关闭该功能。
	//系统保护通常指对操作系统、进程和文件进行安全保护和监控，以防止恶意攻击或非法访问。
	agentEnv.systemProfiles = true
	if *disable_system_protection {
		log.Info("System protection is disabled (process/file profiles)")
		agentEnv.systemProfiles = false
	}

	if *join != "" {
		// Join addresses might not be all ready. Accept whatever input is, resolve them
		// when starting the cluster.
		/*
			addrs := utils.ResolveJoinAddr(*join)
			if addrs == "" {
				log.WithFields(log.Fields{"join": *join}).Error("Invalid join address. Exit!")
				os.Exit(-2)
			}
		*/
		joinAddr = *join
	}
	//判断adv标志是否被设置，如果有值则将其解析为广告地址(advertise address)，并将解析后的结果赋值给advAddr变量。由于一个节点可能有多个IP地址，因此程序会调用utils.ResolveIP函数获取具体的IP地址，并选择其中的第一个地址作为广告地址。如果解析失败或者没有可用的IP地址，则同样会输出错误日志并退出程序。
	if *adv != "" {
		ips, err := utils.ResolveIP(*adv)
		if err != nil || len(ips) == 0 {
			log.WithFields(log.Fields{"advertise": *adv}).Error("Invalid join address. Exit!")
			os.Exit(-2)
		}

		advAddr = ips[0].String()
	}
	//判断bind标志是否被设置，如果有值则将其直接赋值给bindAddr变量，并输出信息日志。
	if *bind != "" {
		bindAddr = *bind
		log.WithFields(log.Fields{"bind": bindAddr}).Info()
	}

	// Set global objects at the very first
	//在程序启动时设置全局对象，并根据结果判断是否初始化成功。如果成功，则将返回的各个参数值分别赋给platform、flavor、network和containers变量；否则输出错误日志并退出程序，其中如果发现容器列表为空，则直接退出进程但不需要重新启动容器。
	platform, flavor, network, containers, err := global.SetGlobalObjects(*rtSock, resource.Register)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to initialize")
		if err == global.ErrEmptyContainerList {
			// Temporary get container list error
			// => exit the process but the container doesn't need to be restarted
			os.Exit(-1)
		}
		os.Exit(-2)
	}

	walkerTask = workerlet.NewWalkerTask(*show_monitor_trace, global.SYS)
	//WalkerTask是一个用于遍历容器文件系统并收集指标数据的工作任务，可以在容器监控和诊断中使用。

	log.WithFields(log.Fields{"endpoint": *rtSock, "runtime": global.RT.String()}).Info("Container socket connected")
	if platform == share.PlatformKubernetes {  //如果当前平台是Kubernetes，则获取其版本信息并注册资源，并根据注册结果判断是否为OpenShift平台，并设置相应的平台类型。
		k8sVer, ocVer := global.ORCH.GetVersion(false, false)
		if k8sVer != "" && ocVer == "" {
			if err := global.ORCH.RegisterResource("image"); err == nil { //如果是OpenShift，则调用global.ORCH.RegisterResource("image")方法注册“image”资源，
				// Use ImageStream as an indication of OpenShift
				flavor = share.FlavorOpenShift //并根据注册结果设置平台类型flavor为OpenShift
				global.ORCH.SetFlavor(flavor)
			} else {
				log.WithFields(log.Fields{"error": err}).Info("register image failed")
			}
		}
		log.WithFields(log.Fields{"k8s": k8sVer, "oc": ocVer, "flavor": flavor}).Info()
	}

	var selfID string
	agentEnv.runWithController = *withCtlr
	agentEnv.runInContainer = global.SYS.IsRunningInContainer()
	if agentEnv.runInContainer {
		selfID, agentEnv.containerInContainer, err = global.SYS.GetSelfContainerID()
		if selfID == "" { // it is a POD ID in the k8s cgroup v2; otherwise, a real container ID
			log.WithFields(log.Fields{"error": err}).Error("Unsupported system. Exit!")
			os.Exit(-2)
		}
		agentEnv.containerShieldMode = (!*skip_nvProtect)
		log.WithFields(log.Fields{"shield": agentEnv.containerShieldMode}).Info("PROC:")
	} else {
		log.Info("Not running in container.")
	}

	if platform == share.PlatformKubernetes {
		if selfID, err = global.IdentifyK8sContainerID(selfID); err != nil {
			log.WithFields(log.Fields{"selfID": selfID, "error": err}).Error("lookup")
		}
	}

	// Container port can be injected after container is up. Wait for at least one.
	pid2ID := make(map[int]string)
	for _, meta := range containers {
		if meta.Pid != 0 {
			pid2ID[meta.Pid] = meta.ID
		}
	}

	for {
		// Get local host and agent info
		if err = getLocalInfo(selfID, pid2ID); err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Failed to get local device information")
			os.Exit(-2)
		}

		if len(Agent.Ifaces) > 0 {
			break
		}

		log.Info("Wait for local interface ...")
		time.Sleep(time.Second * 4)
	}

	// Check anti-affinity
	var retry int
	retryDuration := time.Duration(time.Second * 2)
	for {
		err = checkAntiAffinity(containers, Agent.ID, parentAgent.ID)
		if err != nil {
			// Anti affinity check failure might be because the old enforcer is not stopped yet.
			// This can happen when user switches from an enforcer to an allinone on the same host.
			// Will wait and retry instead of quit to tolerate the timing issue.
			// Also if this enforcer is inside an allinone, the controller can still work correctly.
			retry++
			if retry == 10 {
				retryDuration = time.Duration(time.Second * 30)
				log.Info("Will retry affinity check every 30 seconds")
			}
			time.Sleep(retryDuration)

			// List only running containers
			containers, err = global.RT.ListContainers(true)
			if err != nil {
				log.WithFields(log.Fields{"error": err}).Error("Failed to list containers")
				os.Exit(-2)
			}
		} else {
			break
		}
	}

	Host.Platform = platform
	Host.Flavor = flavor
	Host.Network = network
	Host.CapDockerBench = (global.RT.String() == container.RuntimeDocker)
	Host.CapKubeBench = global.ORCH.SupportKubeCISBench()

	Agent.Domain = global.ORCH.GetDomain(Agent.Labels)
	parentAgent.Domain = global.ORCH.GetDomain(parentAgent.Labels)

	policyInit()

	// Assign agent interface/IP scope
	if agentEnv.runInContainer {
		meta := container.ContainerMeta{
			ID:      Agent.ID,
			Name:    Agent.Name,
			NetMode: Agent.NetworkMode,
			Labels:  Agent.Labels,
		}
		global.ORCH.SetIPAddrScope(Agent.Ifaces, &meta, gInfo.networks)
	}

	Host.StorageDriver = global.RT.GetStorageDriver()
	log.WithFields(log.Fields{"hostIPs": gInfo.hostIPs}).Info("")
	log.WithFields(log.Fields{"host": Host}).Info("")
	log.WithFields(log.Fields{"agent": Agent}).Info("")

	// Other objects
	eventLogKey := share.CLUSAgentEventLogKey(Host.ID, Agent.ID)
	evqueue = cluster.NewObjectQueue(eventLogKey, cluster.DefaultMaxQLen)
	messenger = cluster.NewMessenger(Host.ID, Agent.ID)

	//var driver string
	if *pipeType == "ovs" {
		driver = pipe.PIPE_OVS
	} else if *pipeType == "no_tc" {
		driver = pipe.PIPE_NOTC
		if gInfo.ciliumCNI {
			driver = pipe.PIPE_CLM
		}
	} else {
		driver = pipe.PIPE_TC
		if gInfo.ciliumCNI {
			driver = pipe.PIPE_CLM
		}
	}
	log.WithFields(log.Fields{"pipeType": driver, "jumboframe": gInfo.jumboFrameMTU, "ciliumCNI": gInfo.ciliumCNI}).Info("")
	if nvSvcPort, nvSvcBrPort, err = pipe.Open(driver, cnet_type, Agent.Pid, gInfo.jumboFrameMTU); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open pipe driver")
		os.Exit(-2)
	}

	// Start cluster
	var clusterCfg cluster.ClusterConfig
	clusterCfg.ID = Agent.ID
	clusterCfg.Server = false
	clusterCfg.Debug = false
	clusterCfg.Ifaces = Agent.Ifaces
	clusterCfg.JoinAddr = joinAddr
	clusterCfg.AdvertiseAddr = advAddr
	clusterCfg.BindAddr = bindAddr
	clusterCfg.LANPort = *lanPort
	clusterCfg.DataCenter = cluster.DefaultDataCenter
	clusterCfg.EnableDebug = *debug

	if err = clusterStart(&clusterCfg); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to start cluster. Exit!")
		if err == errNotAdmitted || err == errCtrlNotReady {
			// This indicates controllers are up but license is not loaded.
			// => exit the process but the container doesn't need to be restarted
			os.Exit(-1)
		} else {
			// Monitor will exit, so the container will be restarted
			os.Exit(-2)
		}
	}

	done := make(chan bool, 1)
	c_sig := make(chan os.Signal, 1)
	signal.Notify(c_sig, os.Interrupt, syscall.SIGTERM)

	agentTimerWheel = utils.NewTimerWheel()
	agentTimerWheel.Start()

	// Read existing containers again, cluster start can take a while.
	existing, _ := global.RT.ListContainerIDs()

	if existing.Cardinality() > containerTaskChanSizeMin {
		ContainerTaskChan = make(chan *ContainerTask, existing.Cardinality())
	} else {
		ContainerTaskChan = make(chan *ContainerTask, containerTaskChanSizeMin)
	}

	rtStorageDriver = Host.StorageDriver
	log.WithFields(log.Fields{"name": rtStorageDriver}).Info("Runtime storage driver")

	// Datapath
	dpStatusChan := make(chan bool, 2)
	dp.Open(dpTaskCallback, dpStatusChan, errRestartChan)

	// Benchmark
	bench = newBench(Host.Platform, Host.Flavor)
	go bench.BenchLoop()

	if Host.CapDockerBench {
		bench.RerunDocker(false)
	} else {
		// If the older version write status into the cluster, clear it.
		bench.ResetDockerStatus()
	}
	if !Host.CapKubeBench {
		// If the older version write status into the cluster, clear it.
		bench.ResetKubeStatus()
	}

	bPassiveContainerDetect := global.RT.String() == container.RuntimeCriO

	// Probe
	probeTaskChan := make(chan *probe.ProbeMessage, 256) // increase to avoid underflow
	fsmonTaskChan := make(chan *fsmon.MonitorMessage, 8)
	faEndChan := make(chan bool, 1)
	fsmonEndChan := make(chan bool, 1)
	probeConfig := probe.ProbeConfig{
		ProfileEnable:        agentEnv.systemProfiles,
		Pid:                  Agent.Pid,
		PidMode:              Agent.PidMode,
		DpTaskCallback:       dpTaskCallback,
		NotifyTaskChan:       probeTaskChan,
		NotifyFsTaskChan:     fsmonTaskChan,
		PolicyLookupFunc:     hostPolicyLookup,
		ProcPolicyLookupFunc: processPolicyLookup,
		IsK8sGroupWithProbe:  pe.IsK8sGroupWithProbe,
		ReportLearnProc:      addLearnedProcess,
		ContainerInContainer: agentEnv.containerInContainer,
		GetContainerPid:      cbGetContainerPid,
		GetAllContainerList:  cbGetAllContainerList,
		RerunKubeBench:       cbRerunKube,
		GetEstimateProcGroup: cbEstimateDeniedProcessdByGroup,
		GetServiceGroupName:  cbGetLearnedGroupName,
		FAEndChan:            faEndChan,
		DeferContStartRpt:    bPassiveContainerDetect,
		EnableTrace:          *show_monitor_trace,
		KubePlatform:         Host.Platform == share.PlatformKubernetes,
		KubeFlavor:           Host.Flavor,
		WalkHelper:           walkerTask,
	}

	if prober, err = probe.New(&probeConfig); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to probe. Exit!")
		os.Exit(-2)
	}

	fmonConfig := fsmon.FileMonitorConfig{
		ProfileEnable:  agentEnv.systemProfiles,
		IsAufs:         global.RT.GetStorageDriver() == "aufs",
		EnableTrace:    *show_monitor_trace,
		EndChan:        fsmonEndChan,
		WalkerTask:     walkerTask,
		PidLookup:      prober.ProcessLookup,
		SendReport:     prober.SendAggregateFsMonReport,
		SendAccessRule: sendLearnedFileAccessRule,
		EstRule:        cbEstimateFileAlertByGroup,
	}

	if fileWatcher, err = fsmon.NewFileWatcher(&fmonConfig); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Failed to open file monitor!")
		os.Exit(-2)
	}

	prober.SetFileMonitor(fileWatcher)

	scanUtil = scanUtils.NewScanUtil(global.SYS)

	// grpc need to be put after probe (grpc requests like sessionList, ProbeSummary require probe ready),
	// and it also should be before clusterLoop, sending grpc port in update agent
	global.SYS.CallNetNamespaceFunc(Agent.Pid, func(params interface{}) {
		grpcServer, Agent.RPCServerPort = startGRPCServer(uint16(*grpcPort))
	}, nil)

	// Start container task thread
	// Start monitoring container events
	eventMonitorLoop(probeTaskChan, fsmonTaskChan, dpStatusChan)

	// Update host and device info to cluster
	logAgent(share.CLUSEvAgentStart)
	Agent.JoinedAt = time.Now().UTC()
	putLocalInfo()
	logAgent(share.CLUSEvAgentJoin)
	//NVSHAS-6638,monitor host to see whether there is i/f or IP changes
	prober.StartMonitorHostInterface(Host.ID, 1)

	clusterLoop(existing)
	existing = nil

	go statsLoop(bPassiveContainerDetect)
	go timerLoop()

	if agentEnv.systemProfiles {
		go group_profile_loop()
	}

	// Wait for SIGTREM
	go func() {
		<-c_sig
		done <- true
	}()

	log.Info("Ready ...")

	var rc int
	select {
	case <-done:
		rc = 0
	case <-monitorExitChan:
		rc = -2
	case <-restartChan:
		// Agent is kicked because of license limit.
		// Return -1 so that monitor will restart the agent,
		// and agent will reconnect after license update.
		rc = -1
	case <-errRestartChan:
		// Proactively restart agent to recover from error condition.
		// Return -1 so that monitor will restart the agent.
		rc = -1
		dumpGoroutineStack()
	}

	// Check shouldExit() to see the loops that will exit when the flag is set
	atomic.StoreInt32(&exitingFlag, 1)

	log.Info("Exiting ...")

	if walkerTask != nil {
		walkerTask.Close()
	}

	prober.Close() // both file monitors should be released at first
	fileWatcher.Close()
	bench.Close()

	stopMonitorLoop()
	closeCluster()

	waitContainerTaskExit()

	if driver != pipe.PIPE_NOTC  && driver != pipe.PIPE_CLM {
		dp.DPCtrlDelSrvcPort(nvSvcPort)
	}

	pipe.Close()

	releaseAllSniffer()

	grpcServer.Stop()

	// Close DP at the last
	dp.Close()

	global.SYS.StopToolProcesses()
	<-faEndChan
	<-fsmonEndChan
	log.Info("Exited")
	os.Exit(rc)
}
