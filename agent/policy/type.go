package policy

import (
	"sync"
	"net"

	"github.com/neuvector/neuvector/agent/dp"
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

type GroupProcPolicyCallback func(id string) (*share.CLUSProcessProfile, bool)

type WorkloadIPPolicyInfo struct {
	RuleMap    map[string]*dp.DPPolicyIPRule
	Policy     dp.DPWorkloadIPPolicy
	Configured bool
	SkipPush   bool
	HostMode   bool
	CapIntcp   bool
}

type DlpBuildInfo struct {
	DlpRulesInfo []*dp.DPDlpRuleEntry
	DlpDpMacs    utils.Set
	ApplyDir     int
}

//##用于管理网络安全引擎的各个方面，包括IP策略、安全策略和数据泄漏防护规则等。同时，由于引擎需要处理多线程环境下的并发访问，因此使用互斥锁来保证其安全性。
type Engine struct {
	NetworkPolicy  map[string]*WorkloadIPPolicyInfo  //一个map，用于存储工作负载级别的IP策略信息。key表示工作负载名称，value表示该工作负载的IP策略信息。
	ProcessPolicy  map[string]*share.CLUSProcessProfile  //一个map，用于存储进程级别的安全策略信息。key表示进程编号，value表示该进程的安全策略信息。
	DlpWlRulesInfo map[string]*dp.DPWorkloadDlpRule  //一个map，用于存储工作负载级别的数据泄漏防护规则信息。key表示工作负载名称，value表示该工作负载的数据泄漏防护规则信息。
	DlpBldInfo     *DlpBuildInfo  //一个指向DLP（数据泄露防护）模块构建信息的指针。
	HostID         string  //主机ID，表示当前主机的唯一标识符。
	HostIPs        utils.Set  //一个集合，用于存储当前主机的所有IP地址。
	TunnelIP       []net.IPNet  //一个IP地址列表，用于表示隧道连接的IP地址。
	Mutex          sync.Mutex  //一个互斥锁，用于保证多线程环境下访问引擎对象的并发安全性。
	getGroupRule   GroupProcPolicyCallback  //一个回调函数，用于获取进程组级别的安全策略信息。
	PolicyAddrMap  map[string]share.CLUSSubnet  //一个map，用于存储子网名称和子网地址之间的映射关系。key表示子网名称，value表示子网地址。
}

func (e *Engine) Init(HostID string, HostIPs utils.Set, TunnelIP []net.IPNet, cb GroupProcPolicyCallback) {
	e.HostID = HostID
	e.HostIPs = HostIPs
	e.TunnelIP = TunnelIP
	e.ProcessPolicy = make(map[string]*share.CLUSProcessProfile, 0)
	e.DlpWlRulesInfo = make(map[string]*dp.DPWorkloadDlpRule, 0)
	e.DlpBldInfo = &DlpBuildInfo{
		DlpRulesInfo: make([]*dp.DPDlpRuleEntry, 0),
		DlpDpMacs:    utils.NewSet(),
	}
	e.getGroupRule = cb
	e.PolicyAddrMap = make(map[string]share.CLUSSubnet)
}
