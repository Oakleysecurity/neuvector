package policy

// #include "../../defs.h"
import "C"

import (
	"fmt"
	"net"
	"syscall"

	log "github.com/sirupsen/logrus"
	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
)

//test a large number of ip rules being deployed in a single ep
const ENODEMAX int = 80//number of nodes    //表示 EP 中最大节点数。
const EWLPERNODEMAX int = 250//number of wl per node  //表示每个节点最大的白名单数。
const SIMULATEFREQ int = 3//every SIMULATEFREQ wl, add large number of ip rules  //表示对每个白名单进行模拟规则操作的频率。
const UDPFREQ int = 25  //表示 UDP 流量处理规则的频率。
const FQDNFREQ1 int = 15   //分别表示不同类型 FQDN 规则的处理频率。
const FQDNFREQ2 int = 35
const FQDNFREQ3 int = 45
const APPFREQ1 int = 12  //分别表示不同类型应用程序规则的处理频率。
const APPFREQ2 int = 13
const APPFREQ3 int = 14

var gSimCnt int = 0

//##主要作用是模拟在 DPWorkloadIPPolicy 中添加大量的 IP 规则
//policy 是一个指向 DPWorkloadIPPolicy 结构体的指针，它表示一种基于 IP 规则的安全策略。该结构体可以用来控制网络流量，限制源/目标 IP 地址、端口号、协议类型等访问范围，从而实现对网络安全的管理和防护。
//applyDir 是一个整数类型，表示策略的应用方向。它可以取三个值：INGRESS、EGRESS 和 ALL，分别表示入站、出站和所有方向。在实际使用中，可以根据具体的需求来选择不同的应用方向，以达到相应的安全防护效果。
func simulateAddLargeNumIPRules(policy *dp.DPWorkloadIPPolicy, applyDir int) {
	//log.WithFields(log.Fields{"simcnt": gSimCnt}).Debug("")
	if gSimCnt % SIMULATEFREQ == 0 {
		gSimCnt++
	} else {
		gSimCnt++
		return
	}
	var aIP, aIPR net.IP
	if applyDir&C.DP_POLICY_APPLY_EGRESS > 0 {
		for _, iprule := range policy.IPRules {  //遍历每一条规则，取出IP
			if iprule.Ingress == false {
				aIP = iprule.SrcIP
				aIPR = iprule.SrcIPR
				break
			}
		}
	} else if applyDir&C.DP_POLICY_APPLY_INGRESS > 0 {
		for _, iprule := range policy.IPRules {
			if iprule.Ingress == true {
				aIP = iprule.DstIP
				aIPR = iprule.DstIPR
				break
			}
		}
	}
	log.WithFields(log.Fields{"aip": aIP, "aipr": aIPR}).Debug("")

	var gip [4]byte
	var ipRuleMap map[string]*dp.DPPolicyIPRule = make(map[string]*dp.DPPolicyIPRule)
	for i := 0; i < ENODEMAX; i++ { //loop around node
		for j := 0; j < EWLPERNODEMAX; j++ { //loop around wl within a node
			gip[0] = 192
			gip[1] = 168
			gip[2] = byte((i + 1) % 255)
			gip[3] = byte((j + 1) % 255)
			tid := (i + 1) * EWLPERNODEMAX + (j + 1) + (share.PolicyLearnedIDBase+1000)
			rule := dp.DPPolicyIPRule{
				ID:      uint32(tid % share.PolicyGroundRuleIDMax),
				Port:    0,
				PortR:   65535,
				IPProto: syscall.IPPROTO_TCP,
				Action:  C.DP_POLICY_ACTION_LEARN,
			}
			if applyDir&C.DP_POLICY_APPLY_EGRESS > 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(gip[0], gip[1], gip[2], gip[3])
				rule.Ingress = false
			}
			if applyDir&C.DP_POLICY_APPLY_INGRESS > 0 {
				rule.DstIP = aIP
				rule.DstIPR = aIPR
				rule.SrcIP = net.IPv4(gip[0], gip[1], gip[2], gip[3])
				rule.Ingress = true
			}

			if ((i + 1) * (j + 1)) % UDPFREQ == 0 {   //判断是否为udp流量
				rule.IPProto = syscall.IPPROTO_UDP
			}

			if ((i + 1) * (j + 1)) % FQDNFREQ1 == 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(0, 0, 0, 0)
				rule.Ingress = false
				rule.Fqdn = "*.google.com"
			}

			if ((i + 1) * (j + 1)) % FQDNFREQ2 == 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(0, 0, 0, 0)
				rule.Ingress = false
				rule.Fqdn = "*.microsoftonline.com"
			}

			if ((i + 1) * (j + 1)) % FQDNFREQ3 == 0 {
				rule.SrcIP = aIP
				rule.SrcIPR = aIPR
				rule.DstIP = net.IPv4(0, 0, 0, 0)
				rule.Ingress = false
				rule.Fqdn = "*.cntv.cn"
			}
			var key string
			if rule.Ingress == true {
				if rule.IPProto == syscall.IPPROTO_TCP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "tcp/any", rule.Fqdn, 1)
				}
				if rule.IPProto == syscall.IPPROTO_UDP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "udp/any", rule.Fqdn, 1)
				}
			} else {
				if rule.IPProto == syscall.IPPROTO_TCP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "tcp/any", rule.Fqdn, 0)
				}
				if rule.IPProto == syscall.IPPROTO_UDP {
					key = fmt.Sprintf("%v%v%s%s%d", rule.SrcIP, rule.DstIP, "udp/any", rule.Fqdn, 0)
				}
			}
			if rule.SrcIPR != nil {
				key = fmt.Sprintf("%s%v", key, rule.SrcIPR)
			}
			if rule.DstIPR != nil {
				key = fmt.Sprintf("%s%v", key, rule.DstIPR)
			}

			var application uint32 = 0

			if ((i + 1) * (j + 1)) % APPFREQ1 == 0 {
				application = C.DPI_APP_HTTP
			}

			if ((i + 1) * (j + 1)) % APPFREQ2 == 0 {
				application = C.DPI_APP_SSH
			}

			if ((i + 1) * (j + 1)) % APPFREQ3 == 0 {
				application = C.DPI_APP_REDIS
			}

			if existRule, ok := ipRuleMap[key]; ok {
				if existRule.Action != C.DP_POLICY_ACTION_CHECK_APP {
					continue
				}
				var found bool = false
				for _, app := range existRule.Apps {
					if app.App == application {
						found = true
						break
					}
				}
				if found == false {
					appRule := &dp.DPPolicyApp{
						App:    application,
						Action: C.DP_POLICY_ACTION_LEARN,
						RuleID: existRule.ID,
					}
					existRule.Apps = append(existRule.Apps, appRule)
				}
				continue
			}
			if application > 0 {
				appRule := &dp.DPPolicyApp{
					App:    application,
					Action: C.DP_POLICY_ACTION_LEARN,
					RuleID: rule.ID,
				}
				rule.Apps = append(rule.Apps, appRule)
				rule.Action = C.DP_POLICY_ACTION_CHECK_APP
			}

			//log.WithFields(log.Fields{"rule": rule}).Debug("")
			policy.IPRules = append(policy.IPRules, &rule)   //在确定了规则类型和属性之后，将规则添加到IPRules列表中
			ipRuleMap[key] = &rule
		}
	}
	ipRuleMap = nil
}
