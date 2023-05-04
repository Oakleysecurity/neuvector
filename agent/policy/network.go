package policy

// #include "../../defs.h"
import "C"

import (
	"encoding/json"
	"bytes"
	"fmt"
	"net"
	"reflect"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

type fqdnInfo struct { // 结构体表示一个 FQDN（Fully Qualified Domain Name，完全限定域名）的相关信息，包括 IP 地址列表和是否已被使用；
	ips  []net.IP
	used bool
}

var fqdnMap map[string]*fqdnInfo = make(map[string]*fqdnInfo)  //这个全局变量 fqdnMap 被初始化为一个空的字符串到 fqdnInfo 指针的映射，在程序运行时可以动态添加或删除 FQDN 信息。

func isWorkloadFqdn(wl string) bool {
	return strings.HasPrefix(wl, share.CLUSWLFqdnPrefix)  //检查给定的字符串是否以指定的前缀 share.CLUSWLFqdnPrefix 开头
}

//##从指定的字符串中提取 FQDN 的名称。它首先使用 strings.ToLower 函数将输入字符串转换为小写字母格式，然后使用 len(share.CLUSWLFqdnPrefix) 获取 FQDN 前缀的长度，并从输入字符串中移除该前缀部分，返回剩余的部分作为 FQDN 名称。
func getFqdnName(wl string) string {
	//fqdn domain name should be case insensitive
	return strings.ToLower(wl[len(share.CLUSWLFqdnPrefix):])
}

//##获取指定 FQDN 对应的 IP 地址列表
//name 表示域名
func getFqdnIP(name string) []net.IP {
	if info, ok := fqdnMap[name]; ok { //这段代码使用 Go 语言中的 map 类型变量 fqdnMap 来检查一个 FQDN 是否已经被解析过。具体来说，它通过传入的参数 name 从 fqdnMap 中查找对应的值，并通过 ok 变量来判断是否找到了该值。
		info.used = true
		return info.ips
	}

	ret := make([]net.IP, 0)
	if strings.HasPrefix(name, "*") {
		ret = append(ret, net.IPv4zero)
	} else {
		ips, err := utils.ResolveIP(name)  //解析FQDN，获取IP列表
		if err != nil || ips == nil {
			log.WithFields(log.Fields{"domain": name, "err": err}).Error("Fail to resolve")
			// Put a zero entry as place holder
			ret = append(ret, net.IPv4zero)
		} else {
			for _, ip := range ips {  //遍历解析到的IP地址列表，将ipv4地址添加到ret中
				if utils.IsIPv4(ip) {
					ret = append(ret, ip)
				}
			}
		}
	}
	fqdnMap[name] = &fqdnInfo{ips: ret, used: true}  //将FQDN和IP列表一起存储到fqdnMap中
	return ret
}

//##用于判断一个字符串是否为集群中工作负载对应的 IP 地址
func isWorkloadIP(wl string) bool {
	if strings.HasPrefix(wl, share.CLUSLearnedWorkloadPrefix) {
		if names := strings.Split(wl, share.CLUSLearnedWorkloadPrefix); len(names) == 2 {  //将字符串以"Workload:"分割，并将字串存储在names切片中
			if names[1] != share.CLUSEndpointIngress && net.ParseIP(names[1]) != nil { //判断"ingress"
				return true
			}
		}
	}
	return false
}

//##判断给定的 addr 是否与主机相关
//这个函数的作用是判断给定的 addr 是否与主机相关。具体来说，它首先使用 strings.HasPrefix 函数检查 addr.WlID 是否以指定前缀 share.CLUSLearnedHostPrefix 开头。如果是，则说明该 addr 属性与主机相关，函数返回 true。
//否则，它检查 addr.NatPortApp 是否不为空且长度大于 0。如果是，则说明该 addr 属性与应用程序或网络地址转换（NAT）相关，也返回 true；否则，返回 false。
func isHostRelated(addr *share.CLUSWorkloadAddr) bool {
	if strings.HasPrefix(addr.WlID, share.CLUSLearnedHostPrefix) {
		return true
	} else if addr.NatPortApp != nil && len(addr.NatPortApp) > 0 {
		return true
	}
	return false
}

//##比较给定的字符串 wl 是否与指定的主机 ID（hid）相关联
func isSameHostEP(wl, hid string) bool {
	return wl == fmt.Sprintf("%s%s", share.CLUSLearnedHostPrefix, hid)
}

//##在计算策略之前对全局变量 fqdnMap 中存储的 FQDN 信息进行预处理
//具体来说，它会遍历 fqdnMap 中所有的 FQDN 信息，并将它们的 used 属性设置为 false。这表示每个 FQDN 在计算策略之前都未被使用过，需要重新计算其 IP 地址列表。
func fqdnInfoPrePolicyCalc() {
	for _, info := range fqdnMap {
		info.used = false
	}
}

//##清理fqdnMap中未被使用的域名，并确保fqdnMap中存储的域名数量不超过预定义的最大值。
func fqdnInfoPostPolicyCalc(hid string) {
	del := make([]string, 0)
	for name, info := range fqdnMap {
		if info.used == false {
			del = append(del, name)
		}
	}
	if len(del) > 0 && dp.DPCtrlDeleteFqdn(del) == 0 {
		for _, name := range del {
			if strings.HasPrefix(name, "*") {//wildcard
				rule_key := share.CLUSFqdnIpKey(hid, name)
				if cluster.Exist(rule_key) {
					cluster.Delete(rule_key)
				}
			}
			delete(fqdnMap, name)
		}
	}

	if len(fqdnMap) > C.DP_POLICY_FQDN_MAX_ENTRIES {
		// Todo: trigger event logging
		log.WithFields(log.Fields{
			"capcity": C.DP_POLICY_FQDN_MAX_ENTRIES, "used": len(fqdnMap),
		}).Error("Domain exceeds capacity")
	}
}

func getDerivedAppRule(port string, appRule *dp.DPPolicyApp) *dp.DPPolicyApp {

	/*
	 * for some app, we cannot reliablely identify the app from packet
	 * loose the rule to unknown app as well
	 */
	// Now this is done at control - 09/25/2017
	/*
		if appRule.App == C.DPI_APP_CONSUL && strings.Contains(port, "any") == false {
			derivedAppRule := &dp.DPPolicyApp{
				App:    C.DP_POLICY_APP_UNKNOWN,
				Action: appRule.Action,
				RuleID: appRule.RuleID,
			}
			return derivedAppRule
		}
	*/
	return nil
}

type ruleContext struct {
	ingress bool
	id      uint32
	fqdn    string
}


//##创建IP规则，并将其添加到WorkloadIPPolicyInfo结构体中
//from 源IP地址
//to 目标IP地址
//fromR 源IP范围
//toR 目标IP范围
//portApps 一个包含端口应用程序信息的切片，用于确定要在哪些端口上执行规则。
// action：规则要执行的操作类型。
// pInfo：一个指向WorkloadIPPolicyInfo结构的指针，其中包括有关要创建规则的工作负载的相关信息。
// ctx：一个ruleContext结构体的指针，包含有关要创建规则的网络上下文信息，如fqdn和ingress等。
func createIPRule(from, to, fromR, toR net.IP, portApps []share.CLUSPortApp, action uint8,
	pInfo *WorkloadIPPolicyInfo, ctx *ruleContext) {

	id := ctx.id

	/*
		log.WithFields(log.Fields{
			"id": id, "from": from, "to": to, "fromR": fromR, "toR": toR,
			"portApps": portApps, "action": action, "domain": ctx.fqdn,
		}).Debug("")
	*/
	if portApps == nil {
		/*log.WithFields(log.Fields{
			"id": id, "from": from, "to": to, "portApps": "nil",
		}).Debug("invalid rule!")*/
		return
	}

	for _, portApp := range portApps {
		ports := portApp.Ports
		portList := strings.Split(ports, ",")
		for _, ap := range portList {
			var key string
			if ctx.ingress == true {
				key = fmt.Sprintf("%v%v%s%s%d", from, to, ap, ctx.fqdn, 1)
			} else {
				key = fmt.Sprintf("%v%v%s%s%d", from, to, ap, ctx.fqdn, 0)
			}
			if fromR != nil {
				key = fmt.Sprintf("%s%v", key, fromR)
			}
			if toR != nil {
				key = fmt.Sprintf("%s%v", key, toR)
			}

			if existRule, ok := pInfo.RuleMap[key]; ok {   //如果规则存在就合并  //ok-idiom是一种常见的Go语言编程模式，用于检查映射是否包含给定键
				// rule already exists, merge if needed
				if existRule.Action != C.DP_POLICY_ACTION_CHECK_APP {
					continue
				}
				if id != 0 {
					var found bool = false
					for _, app := range existRule.Apps {
						if app.App == portApp.Application {
							found = true
							break
						}
					}
					if found == false {
						appRule := &dp.DPPolicyApp{
							App:    portApp.Application,
							Action: action,
							RuleID: id,
						}
						existRule.Apps = append(existRule.Apps, appRule)
						derivedAppRule := getDerivedAppRule(ap, appRule)
						if derivedAppRule != nil {
							existRule.Apps = append(existRule.Apps, derivedAppRule)
						}
					}
					continue
				}
			}

			proto, p, pr, err := utils.ParsePortRangeLink(ap)
			if err != nil {
				log.WithFields(log.Fields{
					"id": id, "from": from, "to": to, "ports": ap,
				}).Error("Fail to parse!")
				continue
			}
			rule := dp.DPPolicyIPRule{
				ID:      id,
				SrcIP:   from,
				DstIP:   to,
				SrcIPR:  fromR,
				DstIPR:  toR,
				Port:    p,
				PortR:   pr,
				IPProto: proto,
				Action:  action,
				Ingress: ctx.ingress,
				Fqdn:    ctx.fqdn,
			}

			// For host mode container, only check ports, not applications.
			if !pInfo.HostMode && portApp.CheckApp == true {
				appRule := &dp.DPPolicyApp{
					App:    portApp.Application,
					Action: action,
					RuleID: id,
				}
				rule.Apps = append(rule.Apps, appRule)
				derivedAppRule := getDerivedAppRule(ap, appRule)
				if derivedAppRule != nil {
					rule.Apps = append(rule.Apps, derivedAppRule)
				}
				rule.Action = C.DP_POLICY_ACTION_CHECK_APP
			}
			pInfo.Policy.IPRules = append(pInfo.Policy.IPRules, &rule) //该函数将新创建的rule实例添加到pInfo.Policy.IPRules切片中，并使用规则键将其添加到pInfo.RuleMap映射中。如果已经存在具有相同规则键的规则，则可以选择合并新规则和现有规则。
			pInfo.RuleMap[key] = &rule
		}
	}
}
//最后，该函数将新创建的rule实例添加到pInfo.Policy.IPRules切片中，并使用规则键将其添加到pInfo.RuleMap映射中。如果已经存在具有相同规则键的规则，则可以选择合并新规则和现有规则。


//##用于根据来源和目标IP地址的策略模式调整规则的执行操作类型
//action   要执行的原始操作类型，from和to分别是源和目标IP地址，id是规则ID。
//变换逻辑详见ppt1
func adjustAction(action uint8, from, to *share.CLUSWorkloadAddr, id uint32) uint8 {
	var adjustedAction uint8 = action
	fromMode := from.PolicyMode
	toMode := to.PolicyMode

	switch fromMode {   //根据源IP的策略模式，改变action
	case share.PolicyModeLearn:  //discover模式
		if action == C.DP_POLICY_ACTION_DENY {  //如果动作为拒绝
			adjustedAction = C.DP_POLICY_ACTION_VIOLATE  //将拒绝的动作改为违反
		//学习 --> 任意模式  的学习规则  动作都将改为允许
		} else if id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase {   //判断该策略id是否在学习规则id范围内，share.PolicyFedRuleIDBase=100000
			adjustedAction = C.DP_POLICY_ACTION_LEARN   //将拒绝的动作改为学习
		}
	case share.PolicyModeEvaluate:  //监控模式
		if action == C.DP_POLICY_ACTION_DENY {  //如果动作为拒绝
			adjustedAction = C.DP_POLICY_ACTION_VIOLATE //将拒绝的动作改为违反
		//监控-->学习 的学习规则  动作都将改为允许
		} else if toMode == share.PolicyModeLearn && id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase { //share.PolicyModeLearn为‘discover’
			// Assume learn rule action is always ALLOW, so the original action
			// is not checked here
			adjustedAction = C.DP_POLICY_ACTION_LEARN   //将拒绝的动作改为学习
		}
	case share.PolicyModeEnforce: //保护模式
		//只有 保护 --> 学习 的学习规则  动作都改为
		if toMode == share.PolicyModeLearn && id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase { //share.PolicyModeLearn为‘discover’
			adjustedAction = C.DP_POLICY_ACTION_LEARN
		}
	case "":  //如果fromMode为空字符串，进一步检查toMode
		// src has no policy mode - meaning it's not a managed container
		switch toMode {  //根据目的IP的策略模式修改action
		case share.PolicyModeLearn:
			if action == C.DP_POLICY_ACTION_DENY {
				adjustedAction = C.DP_POLICY_ACTION_VIOLATE
			} else if id >= share.PolicyLearnedIDBase && id < share.PolicyFedRuleIDBase {
				adjustedAction = C.DP_POLICY_ACTION_LEARN
			}
		case share.PolicyModeEvaluate:
			if action == C.DP_POLICY_ACTION_DENY {
				adjustedAction = C.DP_POLICY_ACTION_VIOLATE
			}
		case share.PolicyModeEnforce:
		case "":
			log.WithFields(log.Fields{
				"id": id, "from": from.WlID, "to": to.WlID,
			}).Error("Missing policy mode for both src and dst!")
		default:
			log.WithFields(log.Fields{"id": id, "to": *to}).Error("Invalid policy mode!")
		}
	default:
		log.WithFields(log.Fields{"id": id, "from": *from}).Error("Invalid policy mode!")
	}
	//log.WithFields(log.Fields{"id": id, "from": *from, "to": *to, "action": action,
	//           "adjustedAction": adjustedAction,}).Debug("")
	return adjustedAction
}

//用于创建一个工作负载规则
//它接受来自地址from、去向地址to和一些策略信息，根据这些信息创建网络规则
/*
from：表示源地址，通常是一个IP地址对象。
to：表示目标地址，通常也是一个IP地址对象。
pInfo：表示IP策略信息，包括使用的协议、端口号、主机模式等。
ingress：一个布尔值，表示这是一个入站规则还是出站规则。如果为true，则表示该规则用于入站流量；如果为false，则表示该规则用于出站流量。
sameHost：一个布尔值，表示是否为同一主机上的服务创建网络规则。如果为true，则需要包括所有本地IP地址（包括桥接地址），以便可以访问该服务。如果为false，则只需添加目标或源IP地址即可。
在函数内部，这些参数用于确定要执行的操作类型（允许或拒绝）、设置规则上下文(ctx)、创建网络规则(createIPRule())等。它们是该函数实现网络策略检查和创建防火墙规则所必需的输入信息。
*/
//考虑了主机模式、NAT IP地址、本地/桥接IP地址等因素。
func (e *Engine) createWorkloadRule(from, to *share.CLUSWorkloadAddr, policy *share.CLUSGroupIPPolicy,
	pInfo *WorkloadIPPolicyInfo, ingress, sameHost bool) {

	action := adjustAction(policy.Action, from, to, policy.ID)   //变换调整action

	// deny cannot be enforced for non-interceptable container
	if !pInfo.CapIntcp && action == C.DP_POLICY_ACTION_DENY {  //容器不能被拦截，并且action为拒绝
		action = C.DP_POLICY_ACTION_VIOLATE  //更改action为违反
	}

	ctx := &ruleContext{ingress: ingress, id: policy.ID}
	if ingress == false && isWorkloadFqdn(to.WlID) {
		ctx.fqdn = getFqdnName(to.WlID)
	} else if ingress == true && isWorkloadFqdn(from.WlID) {
		ctx.fqdn = getFqdnName(from.WlID)
	}

	if ingress == false {  //出站流量规则
		var fromIPList []net.IP

		if pInfo.HostMode {  //主机模式的容器
			// for host mode container, we will not check src ip
			if len(from.NatIP) == 0 {
				// Supress the log, a host mode container in the exit state can trigger this forever
				// log.WithFields(log.Fields{"from": from.WlID}).Debug("Missing ip for host mode container!")
				return
			}
			fromIPList = from.NatIP[:1]
		} else {
			fromIPList = from.LocalIP
		}

		for _, ipFrom := range fromIPList {
			if sameHost {  //表示目标IP地址位于本地主机上，因此将在规则列表中添加所有本地IP地址（包括桥接地址），以确保可以访问该服务
				for _, ipTo := range to.LocalIP {
					createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
					//createIPRule(from, to, fromR, toR net.IP, portApps []share.CLUSPortApp, action uint8,pInfo *WorkloadIPPolicyInfo, ctx *ruleContext)
				}
			}

			// For host mode container, the address will be set to NatIP even though the system
			// can be a global ip system (such as k8s).  So add the rule from the host
			// ip to global here as well.
			//总之，这段代码的目的是根据to参数中的不同IP地址和端口应用程序创建网络规则，并确保这些规则覆盖了所有必要的情况。同时，它还考虑了主机模式、NAT IP地址、本地/桥接IP地址等因素
			if pInfo.HostMode {
				for _, ipTo := range to.GlobalIP {
					createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
				}
			}

			if to.NatPortApp == nil {
				continue
			}
//如果to.WlID等于share.CLUSWLAddressGroup或share.CLUSHostAddrGroup，则需要针对to参数中的每个NAT IP地址和端口应用程序创建网络规则，包括本地IP地址和桥接地址等。特别地，如果to.WlID等于share.CLUSHostAddrGroup，则还需要为所有其他本地/桥接IP地址添加相同的规则。
			if to.WlID == share.CLUSWLAddressGroup || to.WlID == share.CLUSHostAddrGroup {
				for i := 0; i < len(to.NatIP); i += 2 {
					createIPRule(ipFrom, to.NatIP[i], nil, to.NatIP[i+1], to.NatPortApp, action, pInfo, ctx)
				}
				if to.WlID == share.CLUSHostAddrGroup {
					//NVSHAS-5205, destination is 'nodes', for local host
					//add the rule to all other local/bridge ip as well
					for _, addr := range e.HostIPs.ToSlice() {
						createIPRule(ipFrom, net.ParseIP(addr.(string)), nil, nil, to.NatPortApp,
							action, pInfo, ctx)
					}
				}
			} else {
				for _, ipTo := range to.NatIP {
					createIPRule(ipFrom, ipTo, nil, nil, to.NatPortApp, action, pInfo, ctx)
					ipToStr := ipTo.String()
					if sameHost {
						//destination is on local host, add the rule to all other local/bridge ip as well
						for _, addr := range e.HostIPs.ToSlice() {
							if addr.(string) == ipToStr {
								continue
							}
							createIPRule(ipFrom, net.ParseIP(addr.(string)), nil, nil, to.NatPortApp,
								action, pInfo, ctx)
						}
						if pInfo.HostMode {
							createIPRule(ipFrom, utils.IPv4Loopback, nil, nil, to.NatPortApp,
								action, pInfo, ctx)
						}
						//no need to continue the loop as all ip on this local host is already included above
						break
					}
				}
			}
		}
	} else {  //入站流量规则
		var toIPList []net.IP
		var toPortApp []share.CLUSPortApp

		if pInfo.HostMode {
			// for host mode container, we will not check dst ip
			if len(to.NatIP) == 0 {
				// Supress the log, a host mode container in the exit state can trigger this forever
				// log.WithFields(log.Fields{"to": to.WlID}).Debug("Missing ip for host mode container!")
				return
			}
			toIPList = to.NatIP[:1]
			//(NVSHAS-4175) for host mode container we also need
			//to include LocalPortApp to create ip rule. For host
			//mode workload we do not check application but only
			//check ports, only add LocalPortApp when there is
			//service port(NatPortApp) open
			if (to.NatPortApp != nil && len(to.NatPortApp) > 0)	&&
				(to.LocalPortApp != nil && len(to.LocalPortApp) > 0) {
				toPortApp = append(toPortApp, to.LocalPortApp...)
			}
			toPortApp = append(toPortApp, to.NatPortApp...)
		} else {
			toIPList = to.LocalIP
			toPortApp = to.LocalPortApp
		}

		if toPortApp != nil {
			for _, ipTo := range toIPList {
				if sameHost {
					for _, ipFrom := range from.LocalIP {
						createIPRule(ipFrom, ipTo, nil, nil, toPortApp, action, pInfo, ctx)
					}
				}

				if from.WlID == share.CLUSWLAddressGroup  || from.WlID == share.CLUSHostAddrGroup {
					for i := 0; i < len(from.NatIP); i += 2 {
						createIPRule(from.NatIP[i], ipTo, from.NatIP[i+1], nil, toPortApp, action, pInfo, ctx)
						if pInfo.HostMode && from.NatIP[i].Equal(utils.IPv4Loopback) {
							// address group with loopback ip as member, we know it's the "nodes" group.
							// Add 127.0.0.1 -> 127.0.0.1 rule
							createIPRule(from.NatIP[i], utils.IPv4Loopback, nil, nil, toPortApp, action, pInfo, ctx)
						}
					}
					if from.WlID == share.CLUSHostAddrGroup {
						//NVSHAS-5205, source is 'nodes', for local host
						//add the rule from all other local/bridge ip as well
						for _, addr := range e.HostIPs.ToSlice() {
							createIPRule(net.ParseIP(addr.(string)), ipTo, nil, nil, toPortApp,
								action, pInfo, ctx)
						}
					}
				} else {
					for _, ipFrom := range from.NatIP {
						createIPRule(ipFrom, ipTo, nil, nil, toPortApp, action, pInfo, ctx)
						ipFromStr := ipFrom.String()
						if sameHost && isHostRelated(from) {
							//source is on local host, add the rule from all other local/bridge ip as well
							for _, addr := range e.HostIPs.ToSlice() {
								if addr.(string) == ipFromStr {
									continue
								}
								createIPRule(net.ParseIP(addr.(string)), ipTo, nil, nil, toPortApp,
									action, pInfo, ctx)
							}
							//no need to continue the loop as all ip on this local host is already included above
							break
						}
					}

					// For host mode container, the address will be set to NatIP even though the system
					// can be a global ip system (such as k8s). So add the rule from the global address to
					// NatIP here as well.
					if pInfo.HostMode {
						for _, ipFrom := range from.GlobalIP {
							createIPRule(ipFrom, ipTo, nil, nil, toPortApp, action, pInfo, ctx)
						}
					}
				}
			}
		}
	}

	for _, ipFrom := range from.GlobalIP {
		for _, ipTo := range to.GlobalIP {
			if policy.ID == 0 && ipFrom.Equal(ipTo) {
				continue
			}
			createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
		}
		// OpenShift workload to host-mode workload
		if to.WlID != share.CLUSWLAddressGroup && to.WlID != share.CLUSHostAddrGroup {
			for _, ipTo := range to.NatIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.NatPortApp, action, pInfo, ctx)
			}
		}
	}

	if sameHost {
		// For rancher, traffic can go from global to local address if they are on the
		// same host. Add the rule here.
		for _, ipFrom := range from.GlobalIP {
			for _, ipTo := range to.LocalIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}

		for _, ipFrom := range from.LocalIP {
			for _, ipTo := range to.GlobalIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}
	}

	// If policy mode is empty, the workload is not a container. Then although the address is
	// written into nat ip list, they are also global address and can be talked to from other
	// global address. Adding the rule here.
	// share.CLUSWLAddressGroup is not subject to this assumption
	if to.WlID == share.CLUSWLAddressGroup || to.WlID == share.CLUSHostAddrGroup {
		for _, ipFrom := range from.GlobalIP {
			for i := 0; i < len(to.NatIP); i += 2 {
				createIPRule(ipFrom, to.NatIP[i], nil, to.NatIP[i+1], to.NatPortApp, action, pInfo, ctx)
			}
		}
	} else if to.PolicyMode == "" {
		for _, ipFrom := range from.GlobalIP {
			for _, ipTo := range to.NatIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.NatPortApp, action, pInfo, ctx)
			}
		}
	}

	if from.WlID == share.CLUSWLAddressGroup  || from.WlID == share.CLUSHostAddrGroup {
		for _, ipTo := range to.GlobalIP {
			for i := 0; i < len(from.NatIP); i += 2 {
				createIPRule(from.NatIP[i], ipTo, from.NatIP[i+1], nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}
	} else if from.PolicyMode == "" {
		for _, ipTo := range to.GlobalIP {
			for _, ipFrom := range from.NatIP {
				createIPRule(ipFrom, ipTo, nil, nil, to.LocalPortApp, action, pInfo, ctx)
			}
		}
	}
}

//##根据给定的WlID填充工作负载地址信息，并根据需要从addrMap中获取其他地址信息。如果WlID是一个合法的FQDN名称，则还会获取与之关联的NAT IP地址。
func fillWorkloadAddress(addr *share.CLUSWorkloadAddr, addrMap map[string]*share.CLUSWorkloadAddr) {
	if a, ok := addrMap[addr.WlID]; ok {
		addr.PolicyMode = a.PolicyMode
		addr.LocalIP = a.LocalIP
		addr.GlobalIP = a.GlobalIP
		addr.NatIP = a.NatIP
	} else if isWorkloadFqdn(addr.WlID) {
		addr.NatIP = getFqdnIP(getFqdnName(addr.WlID))
	}
}

//##获取与给定地址信息相关联的工作负载和IP策略信息
//addrs 表示当前工作负载的地址信息
//pMap 用于存储所有工作负载的IP策略信息。
func getRelevantWorkload(addrs []*share.CLUSWorkloadAddr,
	pMap map[string]*WorkloadIPPolicyInfo) ([]*share.CLUSWorkloadAddr, []*WorkloadIPPolicyInfo) {

	wlList := make([]*share.CLUSWorkloadAddr, 0)   //保存工作负载信息
	pInfoList := make([]*WorkloadIPPolicyInfo, 0)  //保存IP策略信息
	for _, addr := range addrs {
		if addr.WlID == share.CLUSWLModeGroup {
			for id, pInfo := range pMap {
				mode := pInfo.Policy.Mode
				if strings.Contains(addr.PolicyMode, mode) {
					wlList = append(wlList, &share.CLUSWorkloadAddr{WlID: id,
						LocalPortApp: addr.LocalPortApp, NatPortApp: addr.NatPortApp})
					pInfoList = append(pInfoList, pInfo)
				}
			}
		} else {
			if pInfo, ok := pMap[addr.WlID]; ok {
				wlList = append(wlList, addr)
				pInfoList = append(pInfoList, pInfo)
			}
		}
	}
	return wlList, pInfoList
}

//##用于获取与给定地址信息相关的工作负载。
//addrs 是一个指向share.CLUSWorkloadAddr类型的指针切片，表示当前工作负载的地址信息
//wlMap 是一个映射表，用于存储所有工作负载的地址信息。
func getWorkload(addrs []*share.CLUSWorkloadAddr,
	wlMap map[string]*share.CLUSWorkloadAddr) []*share.CLUSWorkloadAddr {

	wlList := make([]*share.CLUSWorkloadAddr, 0)
	for _, addr := range addrs {
		if addr.WlID == share.CLUSWLModeGroup {
			for id, wl := range wlMap {
				if strings.Contains(addr.PolicyMode, wl.PolicyMode) {
					if addr.NatPortApp == nil  || len(addr.NatPortApp) <= 0 {//PAI
						wlList = append(wlList, &share.CLUSWorkloadAddr{WlID: id,
								LocalPortApp: addr.LocalPortApp, NatPortApp: addr.NatPortApp})
					} else {
						wlList = append(wlList, &share.CLUSWorkloadAddr{WlID: id,
								LocalPortApp: addr.LocalPortApp, NatPortApp: wl.NatPortApp})
					}
				}
			}
		} else {
			wlList = append(wlList, addr)
		}
	}
	return wlList

}

//##用于检查是否存在相同的工作负载，以及是否需要将其视为"混合"模式。
//pp 表示当前IP策略组的信息
//from和to分别是指向share.CLUSWorkloadAddr类型的指针，表示源地址和目标地址。
func mixedModeSameWl(pp *share.CLUSGroupIPPolicy, from, to *share.CLUSWorkloadAddr) bool {

	if pp.ID == 0 && from.WlID == to.WlID {
		return true
	}
	return false
}

//##用于将给定的IP网络地址添加到子网映射表中
//subnets 用于存储所有子网信息
//ipnet 表示要添加的IP网络地址
//scope  表示IP网络地址的作用范围
func addPolicyAddrIPNet(subnets map[string]share.CLUSSubnet, ipnet *net.IPNet, scope string) bool {
	subnet := utils.IPNet2Subnet(ipnet)
	if _, ok := subnets[subnet.String()]; !ok {
		snet := share.CLUSSubnet{Subnet: *subnet, Scope: scope}
		return utils.MergeSubnet(subnets, snet)
	}
	return false
}

//##用于将给定工作负载地址的局域网IP地址添加到IP策略地址映射表中
//from 表示当前工作负载的地址信息；
//newPolicyAddrMap 用于存储所有IP策略地址信息。
func addWlLocalAddrToPolicyAddrMap(from *share.CLUSWorkloadAddr, newPolicyAddrMap map[string]share.CLUSSubnet) {
	for _, lip := range from.LocalIP {
		lipnet := &net.IPNet{IP: lip, Mask: net.CIDRMask(32, 32)}
		//log.WithFields(log.Fields{"ip": lipnet.IP.String(), "mask": lipnet.Mask.String()}).Debug("add local ip")
		addPolicyAddrIPNet(newPolicyAddrMap, lipnet, share.CLUSIPAddrScopeLocalhost)
	}
}

//##全局IP地址
func addWlGlobalAddrToPolicyAddrMap(from *share.CLUSWorkloadAddr, newPolicyAddrMap map[string]share.CLUSSubnet) {
	for _, gip := range from.GlobalIP {
		gipnet := &net.IPNet{IP: gip, Mask: net.CIDRMask(32, 32)}
		//log.WithFields(log.Fields{"ip": gipnet.IP.String(), "mask": gipnet.Mask.String()}).Debug("add global ip")
		addPolicyAddrIPNet(newPolicyAddrMap, gipnet, share.CLUSIPAddrScopeGlobal)
	}
}

//##用于解析组IP策略并创建工作负载规则
func (e *Engine) parseGroupIPPolicy(p []share.CLUSGroupIPPolicy, workloadPolicyMap map[string]*WorkloadIPPolicyInfo,
	newPolicyAddrMap map[string]share.CLUSSubnet) {
	addrMap := make(map[string]*share.CLUSWorkloadAddr)
	for i, pp := range p {
		// The first rule is the default rule that contains all container
		if i == 0 {
			for _, from := range pp.From {
				addrMap[from.WlID] = from
				//add wl global/nat address to policy address map
				//these address will be pushed to DP
				if from.PolicyMode == share.PolicyModeEvaluate ||
					from.PolicyMode == share.PolicyModeEnforce {
					addWlGlobalAddrToPolicyAddrMap(from, newPolicyAddrMap)
				}
				if pInfo, ok := workloadPolicyMap[from.WlID]; ok {
					pInfo.Configured = true
					pInfo.Policy.Mode = from.PolicyMode
					pInfo.Policy.DefAction = policyModeToDefaultAction(from.PolicyMode, pInfo.CapIntcp)
					//only add workload local address relevant to this enforcer
					//to policy address map, these address will be pushed to DP
					if from.PolicyMode == share.PolicyModeEvaluate ||
						from.PolicyMode == share.PolicyModeEnforce {
						addWlLocalAddrToPolicyAddrMap(from, newPolicyAddrMap)
					}
				}
			}
			continue
		}

		/* create egress rules */
		wlList, pInfoList := getRelevantWorkload(pp.From, workloadPolicyMap)
		wlToList := getWorkload(pp.To, addrMap)
		for i, from := range wlList {
			pInfo := pInfoList[i]
			for _, to := range wlToList {
				if pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_EGRESS > 0 {
					var sameHost bool = false
					if isSameHostEP(to.WlID, e.HostID) {
						sameHost = true
					} else if _, ok := workloadPolicyMap[to.WlID]; ok {
						sameHost = true
					}
					fillWorkloadAddress(from, addrMap)
					fillWorkloadAddress(to, addrMap)
					if mixedModeSameWl(&pp, from, to) {
						continue
					}
					e.createWorkloadRule(from, to, &pp, pInfo, false, sameHost)
				} else {
					// Only configure egress rule to external, as east-west egress traffic
					// will be automatically allowed at DP
					if to.WlID == share.CLUSWLExternal || to.WlID == share.CLUSWLAddressGroup ||
						to.WlID == share.CLUSHostAddrGroup || isWorkloadFqdn(to.WlID) || isWorkloadIP(to.WlID) {
						fillWorkloadAddress(from, addrMap)
						fillWorkloadAddress(to, addrMap)
						e.createWorkloadRule(from, to, &pp, pInfo, false, false)
					} else if isHostRelated(to) {
						var sameHost bool = false
						if isSameHostEP(to.WlID, e.HostID) {
							sameHost = true
						} else if _, ok := workloadPolicyMap[to.WlID]; ok {
							sameHost = true
						}
						fillWorkloadAddress(from, addrMap)
						fillWorkloadAddress(to, addrMap)
						e.createWorkloadRule(from, to, &pp, pInfo, false, sameHost)
					}
				}
			}
		}

		/* create ingress rules */
		wlList, pInfoList = getRelevantWorkload(pp.To, workloadPolicyMap)
		wlFromList := getWorkload(pp.From, addrMap)
		for i, to := range wlList {
			pInfo := pInfoList[i]
			for _, from := range wlFromList {
				if pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_INGRESS > 0 {
					var sameHost bool = false
					if isSameHostEP(from.WlID, e.HostID) {
						sameHost = true
					} else if _, ok := workloadPolicyMap[from.WlID]; ok {
						sameHost = true
					}
					fillWorkloadAddress(from, addrMap)
					fillWorkloadAddress(to, addrMap)
					if mixedModeSameWl(&pp, from, to) {
						continue
					}
					e.createWorkloadRule(from, to, &pp, pInfo, true, sameHost)
				} else {
					// Only configure ingress rule from external, as east-west ingress traffic
					// will be automatically allowed at DP
					if from.WlID == share.CLUSWLExternal || from.WlID == share.CLUSWLAddressGroup ||
						from.WlID == share.CLUSHostAddrGroup || isWorkloadFqdn(from.WlID) || isWorkloadIP(from.WlID) {
						fillWorkloadAddress(from, addrMap)
						fillWorkloadAddress(to, addrMap)
						e.createWorkloadRule(from, to, &pp, pInfo, true, false)
					}
				}
			}
		}
	}
	return
}

//##将策略模式转换为默认action
//mode 模式
//capIntcp 是否可以拦截
func policyModeToDefaultAction(mode string, capIntcp bool) uint8 {
	switch mode {
	case share.PolicyModeLearn:
		return C.DP_POLICY_ACTION_LEARN
	case share.PolicyModeEvaluate:
		return C.DP_POLICY_ACTION_VIOLATE
	case share.PolicyModeEnforce:
		if capIntcp {
			return C.DP_POLICY_ACTION_DENY
		} else {
			return C.DP_POLICY_ACTION_VIOLATE
		}
	}
	//for a wl whose mode is empty/unknown
	//set default action to OPEN to reduce
	//false violations
	return C.DP_POLICY_ACTION_OPEN
}

func ipMatch(ip, ipL, ipR net.IP, external bool) bool {
	if external && bytes.Compare(ipL, net.IPv4zero) == 0 {
		return true
	}
	s := bytes.Compare(ip, ipL)
	if s == 0 {
		return true
	} else if ipR == nil {
		return false
	}
	if s > 0 && bytes.Compare(ip, ipR) <= 0 {
		return true
	}
	return false
}

func hostPolicyMatch(r *dp.DPPolicyIPRule, conn *dp.Connection) (bool, uint32, uint8) {
	if r.Ingress != conn.Ingress {
		return false, 0, 0
	}

	if r.Ingress {
		if ipMatch(conn.ClientIP, r.SrcIP, r.SrcIPR, conn.ExternalPeer) == false {
			return false, 0, 0
		}
	} else if ipMatch(conn.ServerIP, r.DstIP, r.DstIPR, conn.ExternalPeer) == false {
		return false, 0, 0
	}
	if conn.ServerPort < r.Port || conn.ServerPort > r.PortR {
		return false, 0, 0
	}
	if r.IPProto > 0 && conn.IPProto != r.IPProto {
		return false, 0, 0
	}

	if r.Action == C.DP_POLICY_ACTION_CHECK_APP {
		for _, app := range r.Apps {
			if app.App == C.DP_POLICY_APP_ANY || app.App == conn.Application {
				return true, app.RuleID, app.Action
			}
		}
		return false, 0, 0
	}

	return true, r.ID, r.Action
}

func (e *Engine) HostNetworkPolicyLookup(wl string, conn *dp.Connection) (uint32, uint8, bool) {
	e.Mutex.Lock()
	pInfo := e.NetworkPolicy[wl]
	e.Mutex.Unlock()

	if pInfo == nil || !pInfo.Configured {
		return 0, C.DP_POLICY_ACTION_OPEN, false
	}

	if conn.Ingress {
		if !conn.ExternalPeer &&
			(pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_INGRESS == 0) {
			return 0, C.DP_POLICY_ACTION_OPEN, false
		}

		for _, p := range pInfo.Policy.IPRules {
			if !p.Ingress {
				continue
			}
			if match, id, action := hostPolicyMatch(p, conn); match {
				return id, action, action > C.DP_POLICY_ACTION_CHECK_APP
			}
		}
	} else {
		if !conn.ExternalPeer &&
			(pInfo.Policy.ApplyDir&C.DP_POLICY_APPLY_EGRESS == 0) {
			return 0, C.DP_POLICY_ACTION_OPEN, false
		}

		for _, p := range pInfo.Policy.IPRules {
			if p.Ingress {
				continue
			}

			if match, id, action := hostPolicyMatch(p, conn); match {
				return id, action, action > C.DP_POLICY_ACTION_CHECK_APP
			}
		}
	}
	action := policyModeToDefaultAction(pInfo.Policy.Mode, pInfo.CapIntcp)
	return 0, action, action > C.DP_POLICY_ACTION_CHECK_APP
}

func (e *Engine) UpdateNetworkPolicy(ps []share.CLUSGroupIPPolicy,
	newPolicy map[string]*WorkloadIPPolicyInfo) utils.Set {

	fqdnInfoPrePolicyCalc()

	newPolicyAddrMap := make(map[string]share.CLUSSubnet)
	e.parseGroupIPPolicy(ps, newPolicy, newPolicyAddrMap)

	dpConnected := dp.Connected()

	if dpConnected {
		fqdnInfoPostPolicyCalc(e.HostID)
	}

	// For host mode containers, we need to notify probe the policy change
	hostPolicyChangeSet := utils.NewSet()
	for id, pInfo := range newPolicy {
		// release the ruleMap as it is not needed anymore
		pInfo.RuleMap = nil

		// For workload that is not configured, policy is not calculated yet.
		// Don't send policy to DP so that DP will bypass the traffic
		if pInfo.Configured == false {
			continue
		}

		if pInfo.SkipPush {
			continue
		}

		if old, ok := e.NetworkPolicy[id]; !ok {
			if pInfo.HostMode {
				hostPolicyChangeSet.Add(id)
			} else if dpConnected {
				//simulateAddLargeNumIPRules(&pInfo.Policy, pInfo.Policy.ApplyDir)
				dp.DPCtrlConfigPolicy(&pInfo.Policy, C.CFG_ADD)
			}
		} else if pInfo.Configured != old.Configured ||
			reflect.DeepEqual(&pInfo.Policy, &old.Policy) != true {
			if pInfo.HostMode {
				hostPolicyChangeSet.Add(id)
			} else if dpConnected {
				//simulateAddLargeNumIPRules(&pInfo.Policy, pInfo.Policy.ApplyDir)
				dp.DPCtrlConfigPolicy(&pInfo.Policy, C.CFG_MODIFY)
			}
		}
	}
	//always push policy address map at the end after all policy has
	//been pushed to DP, so that if there is early traffic at the DP
	//if wl ip is not in addr map we know that policy is not yet pushed
	//to DP so we can let action be OPEN
	if reflect.DeepEqual(e.PolicyAddrMap, newPolicyAddrMap) == false {
		dp.DPCtrlConfigPolicyAddr(newPolicyAddrMap)
	}
	// we don't do policy delete here as it only happens when workload is gone
	// Policy at DP will be deleted automatically for this case
	e.Mutex.Lock()
	e.NetworkPolicy = newPolicy
	e.PolicyAddrMap = newPolicyAddrMap
	e.Mutex.Unlock()

	return hostPolicyChangeSet
}

func (e *Engine) GetNetworkPolicy() map[string]*WorkloadIPPolicyInfo {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.NetworkPolicy
}

func (e *Engine) GetPolicyAddrMap() map[string]share.CLUSSubnet {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.PolicyAddrMap
}

func (e *Engine) DeleteNetworkPolicy(id string) {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	delete(e.NetworkPolicy, id)
}

func (e *Engine) PushNetworkPolicyToDP() {
	log.Debug("")
	np := e.GetNetworkPolicy()
	for _, pInfo := range np {
		if pInfo.Configured == false {
			continue
		}
		if pInfo.SkipPush {
			continue
		}
		dp.DPCtrlConfigPolicy(&pInfo.Policy, C.CFG_ADD)
	}
	policyAddr := e.GetPolicyAddrMap()
	dp.DPCtrlConfigPolicyAddr(policyAddr)
}

func (e *Engine) PushFqdnInfoToDP() {
	fqdn_key := fmt.Sprintf("%s%s/", share.CLUSFqdnIpStore, e.HostID)
	allKeys, _ := cluster.GetStoreKeys(fqdn_key)
	for _, key := range allKeys {
		if value, _ := cluster.Get(key); value != nil {
			uzb := utils.GunzipBytes(value)
			if uzb != nil {
				var fqdnip share.CLUSFqdnIp
				json.Unmarshal(uzb, &fqdnip)
				dp.DPCtrlSetFqdnIp(&fqdnip)
			}
		}
	}
}

//dlp
func (e *Engine) GetNetworkDlpWorkloadRulesInfo() map[string]*dp.DPWorkloadDlpRule {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.DlpWlRulesInfo
}

func (e *Engine) GetNetworkDlpBuildInfo() *DlpBuildInfo {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()

	return e.DlpBldInfo
}

func (e *Engine) PushNetworkDlpToDP() {
	log.Debug("config and build dlp")
	e.Mutex.Lock()

	wlDlpInfo := e.DlpWlRulesInfo
	//endpoint does not associate with any dlp rules which means we
	//do not need to push any info to DP
	if wlDlpInfo == nil || len(wlDlpInfo) == 0 {
		log.Debug("endpoint does not associate with any dlp rules")
		e.Mutex.Unlock()
		return
	}

	for _, wldre := range wlDlpInfo {
		dp.DPCtrlConfigDlp(wldre)
	}

	dlpbldinfo := e.DlpBldInfo
	//no dlp rules to build detection tree
	if dlpbldinfo.DlpRulesInfo == nil || len(dlpbldinfo.DlpRulesInfo) == 0 {
		log.Debug("no dlp rules to build detection tree")
		e.Mutex.Unlock()
		return
	}
	dp.DPCtrlBldDlp(dlpbldinfo.DlpRulesInfo, dlpbldinfo.DlpDpMacs, nil, dlpbldinfo.ApplyDir)

	e.Mutex.Unlock()

	log.Debug("dlp config and build done")
}
