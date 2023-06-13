package main

import (
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	sk "github.com/neuvector/neuvector/share/system/sidekick"
	"github.com/neuvector/neuvector/share/utils"
)

//用于获取主机网络接口的IP地址。
func getHostAddrs() map[string]sk.NetIface {
	var ifaces map[string]sk.NetIface
//执行一个指定命名空间下的网络操作，并在其中调用sk.GetGlobalAddrs()方法获取主机网络接口信息。最后将获得的网络接口信息作为结果返回。
	global.SYS.CallNetNamespaceFunc(1, func(params interface{}) {
		ifaces = sk.GetGlobalAddrs()
	}, nil)

	return ifaces
}

/*
With Azure advanced networking plugin:
 link - link=eth0 type=device
 link - link=docker0 type=bridge
 Switch - ipnet={IP:172.17.0.1 Mask:ffff0000} link=docker0
 link - link=enP1p0s2 type=device
 link - link=azure0 type=bridge
 Switch - ipnet={IP:10.240.0.35 Mask:ffff0000} link=azure0
 link - link=azv1769de20eea type=veth
 link - link=lo type=device

 2: eth0: <BROADCAST,UP,LOWER_UP> mtu 1500 qdisc mq master azure0 state UP qlen 1000
 5: azure0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP qlen 1000
*/

//用于解析主机网络接口的IP地址，并返回相应的结果。
func parseHostAddrs(ifaces map[string]sk.NetIface, platform, network string) (map[string][]share.CLUSIPAddr, utils.Set, bool, bool) {
	devs := make(map[string][]share.CLUSIPAddr)
	ips := utils.NewSet()
	maxMTU := 0
	ciliumCNI := false

	//程序遍历输入的网络接口信息，判断每个接口的类型和MTU值，并根据条件对设备列表和IP地址集合进行相应的更新和添加。特别地，如果当前平台为Kubernetes，且网络接口名称以"cni"开头，则跳过该接口。另外，如果发现网络接口名称为"azure0"，则将其加入到设备列表中。
	for name, iface := range ifaces {
		log.WithFields(log.Fields{"link": name, "type": iface.Type, "mtu": iface.Mtu, "flags": iface.Flags}).Info("link")

		if strings.HasPrefix(name, "cilium") {
			ciliumCNI = true
		}

		if iface.Mtu <= share.NV_VBR_PORT_MTU_JUMBO && maxMTU < iface.Mtu {
			maxMTU = iface.Mtu
		}
		if iface.Type == "device" || iface.Type == "bond" || iface.Type == "vlan" {
			for _, addr := range iface.Addrs {
				if utils.IsIPv4(addr.IPNet.IP) {
					log.WithFields(log.Fields{"link": name, "ipnet": addr.IPNet}).Info("Global")
					devs[name] = append(devs[name], share.CLUSIPAddr{
						IPNet: addr.IPNet,
						Scope: share.CLUSIPAddrScopeNAT,
					})
					ips.Add(addr.IPNet.IP.String())
				}
			}
		} else if iface.Type == "bridge" {
			if platform == share.PlatformKubernetes && strings.HasPrefix(name, "cni") {
				continue
			}
			//kube-router CNI
			if platform == share.PlatformKubernetes && name == "kube-bridge" {
				continue
			}

			for _, addr := range iface.Addrs {
				if utils.IsIPv4(addr.IPNet.IP) {
					log.WithFields(log.Fields{"link": name, "ipnet": addr.IPNet}).Info("Switch")
					if name == "azure0" {
						devs[name] = append(devs[name], share.CLUSIPAddr{
							IPNet: addr.IPNet,
							Scope: share.CLUSIPAddrScopeNAT,
						})
					}
					ips.Add(addr.IPNet.IP.String())
				}
			}
		}
	}
	log.WithFields(log.Fields{"maxMTU": maxMTU, "ciliumCNI": ciliumCNI}).Info("")
	if maxMTU > share.NV_VBR_PORT_MTU { //jumbo frame mtu
		return devs, ips, true, ciliumCNI
	} else {
		return devs, ips, false, ciliumCNI
	}
}
