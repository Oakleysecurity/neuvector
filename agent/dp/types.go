package dp

import (
	"net"

	"github.com/neuvector/neuvector/share"
)

//##用于声明一个DP控制器中某些事件的回调函数
//buf 表示一段字节切片
//param 表示回调函数的其他参数
type DPCallback func(buf []byte, param interface{}) bool
//用于声明一个 DP 控制器中某些任务的回调函数
type DPTaskCallback func(task *DPTask)

const (
	DP_TASK_THREAT_LOG = iota
	DP_TASK_CONNECTION
	DP_TASK_HOST_CONNECTION
	DP_TASK_APPLICATION
	DP_TASK_FQDN_IP
)
 
type Connection struct {   //包含了用于表示网络连接的各种信息字段
	AgentID      string   //代理ID
	HostID       string
	ClientWL     string  //客户端白名单
	ServerWL     string  //服务器白名单
	ClientIP     net.IP
	ServerIP     net.IP
	Scope        string  //表示连接的范围
	Network      string  //表示连接所在的网络
	ServerPort   uint16
	ClientPort   uint16
	IPProto      uint8
	Application  uint32
	Bytes        uint64
	Sessions     uint32
	FirstSeenAt  uint32
	LastSeenAt   uint32
	ThreatID     uint32
	Severity     uint8
	PolicyAction uint8
	Ingress      bool
	ExternalPeer bool
	LocalPeer    bool
	PolicyId     uint32
	Violates     uint32
	Xff          bool
	SvcExtIP     bool
	ToSidecar    bool
	MeshToSvr    bool
	LinkLocal    bool
}

type ConnectionData struct {
	EPMAC net.HardwareAddr  //表示设备mac地址
	Conn  *Connection  //指向与该设备相关联的连接信息
}

type DPTask struct {   //定义了DP控制器中要执行的任务
	Task     int
	MAC      net.HardwareAddr
	SecLog   *share.CLUSThreatLog
	Connects []*ConnectionData
	Apps     map[share.CLUSProtoPort]*share.CLUSApp
	Fqdns    *share.CLUSFqdnIp
}
