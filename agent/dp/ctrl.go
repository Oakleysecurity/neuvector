package dp

// #include "../../defs.h"
import "C"

import (
	"bytes"    //实现字节操作的函数和类型
	"encoding/binary"   //提供了对于二进制数据和整数之间的转换
	"encoding/json"   //提供了json数据编码和解码的功能
	"fmt"     //提供了格式化输入和输出的功能
	"net"  //网络通信相关的函数和类型
	"os"   //操作系统函数和类型
	"sync"   //同步原语，例如互斥锁和条件变量
	"time"  //时间处理相关函数和类型
	"unsafe"  //访问系统底层，绕过类型安全检查等操作

	log "github.com/sirupsen/logrus" //将第三方库导入并起别名为log，方便使用
	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

// TODO: The workflow need to be reworked.
//       1. Disconnect condition of both sides should be handled.
//常量 名称 类型 = value
//变量 名称 类型
const dpClient string = "/tmp/dp_client.%d"    //定义一个字符串类型的常量
const ctrlServer string = "/tmp/ctrl_listen.sock"

const defaultDPMsgTimeout int = 2   //定义一个整型常量
const dpConnJamRetryMax int = 16

var dpConn *net.UnixConn   //定义了一个net.UnixConn类型的指针变量dpConn   //这个变量通常代表与NeuVector代理建立的Unix socket连接
var dpClientMutex sync.Mutex  //定义了一个sync.Mutex类型的互斥锁变量dpClientMutex  //用于在多线程同时访问dpConn变量时保持互斥性

const dpKeepAliveInterval time.Duration = (time.Second * 2) //time.Duration是go中表示时间长度的类型，使用纳秒作为基本单位，可以方便的将时间间隔转化为不同单位的字符串表示
//dpKeepAliveInterval表示容器和Neuvector代理之间保持连接的心跳包发送间隔，初始值为2秒

var keepAliveSeq uint32   //用于代表心跳包的序列号，以便在neuvector代理接收到心跳包时能够验证其完整性，并避免重复和丢失
var dpAliveMsgCnt uint = 0  //表示容器和neuvector代理之间已经发送的心跳包的数量，用于检测连接是否正常工作

var taskCallback DPTaskCallback   //定义一个名为taskCallback的变量，它是一个函数类型DPTaskCallback的值  //这个变量代表neuvector代理执行某些任务时的回调函数
var statusChan chan bool  //定义了一个通道（channel）类型的值，并且该通道只能传输bool类型的值  //在go中通道是一种用于goroutine之间进行通信和同步的基本机制，可以在不同的goroutine中发送和接收数据，并确保数据按照先进先出的顺序进行处理。
var restartChan chan interface{} //该通道可以传输任何类型的值；用于在neuvector代理需要重新启动时触发通知

func dpClientLock() {
	// log.Info("")
	dpClientMutex.Lock()  //获取互斥锁，确保在多个goroutine并发访问该变量时只有一个goroutine能够执行这个函数内部的代码块  //在需要保护共享资源的位置可以调用此函数
}

func dpClientUnlock() {
	// log.Info("")
	dpClientMutex.Unlock()  //释放互斥锁，使得其他goroutine可以访问该共享资源
}

// With lock hold
// msg  表示要发送的消息内容，类型为字节数组
// timeout 表示消息传输的超时时间
// cb 表示在收到neuvector代理的相应后调用的回调函数
// param 表示传递给回调函数的参数
func dpSendMsgExSilent(msg []byte, timeout int, cb DPCallback, param interface{}) int {   //为neuvector代理发送消息
	if dpConn == nil {   //检测是否与neuvector代理建立了连接  //nil是空指针或空值
		log.Error("Data path not connected")
		if cb != nil {
			cb(nil, param)
		}
		return -1
	}

	dpConn.SetWriteDeadline(time.Now().Add(time.Second * 2))  //如果建立了连接，就将消息写入unix socket文件中，并设置超时时间为timeout指定的的值
	_, err := dpConn.Write(msg)
	if err != nil {  //msg发送失败的情况
		log.WithFields(log.Fields{"error": err}).Error("Send error")
		// Let keep alive to close dp to avoid reentry
		// closeDP()
		// debug.PrintStack()
		if cb != nil {
			cb(nil, param)
		}
		return -1
	}

	if cb != nil {  //msg发送成功的情况
		if timeout == 0 {
			timeout = defaultDPMsgTimeout
		}

		var done bool
		var buf []byte = make([]byte, C.DP_MSG_SIZE)

		for !done {  //只要任务没完成，就一直循环，直到收到neuvector代理的相应或者超时结束
			dpConn.SetReadDeadline(time.Now().Add(time.Second * time.Duration(timeout)))  //设置超时时间，让心跳包机制负责监测和关闭连接
			n, err := dpConn.Read(buf)  //从已连接的unix socket中读取数据
			if err != nil {  //读取失败
				log.WithFields(log.Fields{"error": err}).Error("Read error")
				cb(nil, param)
				// Time out could be because DP is busy. Don't close DP yet.
				// Let keep alive cb to close dp later if dp is really gone
				// closeDP()
				return -1
			} else {
				done = cb(buf[:n], param)  //读取成功时，将接收到的消息交给回调函数处理
			}
		}
	}
	dpAliveMsgCnt++   //每向neuvector代理发送一条消息就自增1，以便检测连接是否正常工作
	return 0  //返回0表示操作成功
}

//##调用了dpSendMsgExSilent函数，只是加了互斥锁
func dpSendMsgEx(msg []byte, timeout int, cb DPCallback, param interface{}) int {   
	log.WithFields(log.Fields{"msg": string(msg), "size": len(msg)}).Debug("") //打印调试日志

	// The cb call is inside the dp lock, so be careful if you need to grab
	// another lock in cb
	dpClientLock()
	defer dpClientUnlock()  //确保在函数返回之前总是会释放该锁（不管函数是否发生错误）
	return dpSendMsgExSilent(msg, timeout, cb, param)
}

//##用于向neuvector发送不带超时和回调函数的消息
func dpSendMsg(msg []byte) int {  
	return dpSendMsgEx(msg, 0, nil, nil)
}

// -- DP message functions
//##用于向neuvector代理发送添加tap端口的请求
//netns 表示要添加tap端口的网络命名空间
//iface 表示要添加的tap端口名称
//epmac 表示tap端口的mac地址

//Tap端口：是一种虚拟的网络接口，用于在不同网络栈之间传递数据包；在linux中，可以通过创建虚拟的tap端口来模拟物理网络接口。
	//neuvector代理提供了添加、管理和监控tap端口的功能，以保证集群中的所有节点都能够安全的通信，并遵守预定义的安全策略
func DPCtrlAddTapPort(netns, iface string, epmac net.HardwareAddr) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPAddTapPortReq{
		AddPort: &DPTapPort{
			NetNS: netns,
			Iface: iface,
			EPMAC: epmac.String(),
		},
	}
	msg, _ := json.Marshal(data)  //将参数转化为json
	dpSendMsg(msg)  //给neuvector代理发送添加tap端口的请求
}

//##为代理发送删除tap端口的请求
func DPCtrlDelTapPort(netns, iface string) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPDelTapPortReq{
		DelPort: &DPTapPort{
			NetNS: netns,
			Iface: iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}


//##用于向Neuvector代理发送添加Nfq端口的请求
//netns 表示要添加Nfq端口的网络命名空间
//iface 表示要添加的Nfq端口的名称
//qno 表示Nfq端口所在的队列编号
//epmac  表示Nfq端口的mac地址
//jumboframe 表示是否启用Jumbo Frame（巨型帧）模式，可选，可为nil；若开启则表示可以传输更大的数据包

//Nfq（Netfilter Queue）端口是一种虚拟网络接口，用于将Linux系统内核中的数据包传递给用户空间的程序进行处理
//当 Linux 系统内核中的某个网络栈收到一个数据包时，它可以根据事先定义的规则（如防火墙规则、路由表等）决定该如何处理这个数据包。如果需要对该数据包进行更为精确的过滤、监控或者修改等操作，则可以通过 Nfq 端口将该数据包传递给用户空间的程序进行处理。用户空间程序可以对数据包进行更灵活的处理，并且可以根据自己的需要决定是否将数据包继续发送到下一个网络栈中。
//NeuVector 代理使用 Nfq 端口来实现对集群中的网络流量进行安全性检测和策略执行。当 NeuVector 代理收到一个数据包时，它会通过 Nfq 端口将数据包传递给用户空间的安全检测程序进行分析和处理。在安全检测完成后，NeuVector 代理可以根据预先定义的安全策略，决定是否将数据包发送到下一个网络栈中。
func DPCtrlAddNfqPort(netns, iface string, qno int, epmac net.HardwareAddr, jumboframe *bool) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPAddNfqPortReq{   //创建一个DPAddNfqPortReq结构体变量data
		AddNfqPort: &DPNfqPort{
			NetNS: netns,
			Iface: iface,
			Qnum:  qno,
			EPMAC: epmac.String(),
		},
	}
	if jumboframe != nil {
		data.AddNfqPort.JumboFrame = jumboframe  //如果存在jumboframe参数，就将其赋值给JumboFrame字段
	}
	msg, _ := json.Marshal(data)  //转换为json
	dpSendMsg(msg) //发送
}

//##用于向neuvector代理发送删除nfq端口的请求
func DPCtrlDelNfqPort(netns, iface string) {
	log.WithFields(log.Fields{"netns": netns, "iface": iface}).Debug("")

	data := DPDelNfqPortReq{
		DelNfqPort: &DPNfqPort{
			NetNS: netns,
			Iface: iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##向neuvector代理发送添加服务端口的请求
//iface 表示要添加的服务端口名称
//jumboframe 表示是否启用Jumbo Frame（巨型帧）模式，参数可选
func DPCtrlAddSrvcPort(iface string, jumboframe *bool) {
	log.WithFields(log.Fields{"iface": iface}).Debug("")

	data := DPAddSrvcPortReq{
		AddPort: &DPSrvcPort{
			Iface: iface,
		},
	}
	if jumboframe != nil {
		data.AddPort.JumboFrame = jumboframe
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

func DPCtrlDelSrvcPort(iface string) {
	log.WithFields(log.Fields{"iface": iface}).Debug("")

	data := DPDelSrvcPortReq{
		DelPort: &DPSrvcPort{
			Iface: iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##向neuvector代理发送设置系统配置的请求
//xffenabled 表示是否开启X-Forwarded-For（XFF）头部字段，可选，可为nil
//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息更新系统配置，并决定是否启用 XFF 头部字段。XFF 头部字段是一个常用的 HTTP 头部字段，用于标识客户端的真实 IP 地址，通常用于反向代理和负载均衡等场景中。如果启用了 XFF 头部字段，则 NeuVector 将能够更准确地确定数据包的来源，从而提高安全性检测的精度和效果。
func DPCtrlSetSysConf(xffenabled *bool) {
	log.WithFields(log.Fields{"xffenabled": *xffenabled}).Debug("")

	data := DPSysConfReq{
		Sysconf: &DPSysConf{
			XffEnabled: xffenabled,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##向代理发送添加mac地址的请求
//iface 表示要添加mac地址的网络请求接口名称
//mac 表示要添加的mac地址
//ucmac 表示要添加的mac地址对应的单播地址
//bcmac 表示要添加的mac地址对应的广播地址
//oldmac 表示要替换的旧mac地址，可选，可为nil
//pmac 表示要添加的mac地址所属的物理主机的mac地址，可选，可为nil
//pips 表示要添加的mac地址所属的物理主机的IP地址列表，可选，可为nil
func DPCtrlAddMAC(iface string, mac, ucmac, bcmac, oldmac, pmac net.HardwareAddr, pips []net.IP) {
	log.WithFields(log.Fields{"mac": mac, "iface": iface}).Debug("")

	tpips := make([]DPMacPip, 0, len(pips))  //创建一个空的类型为[]DPMacPip的切片变量tpips
	for _, addr := range pips {   //遍历pips参数中的每个IP地址，将其封装成DPMacPip结构体，并添加到tpips中
		pip := DPMacPip{
			IP: addr,
		}
		tpips = append(tpips, pip)
	}

	data := DPAddMACReq{
		AddMAC: &DPAddMAC{
			Iface:  iface,
			MAC:    mac.String(),
			UCMAC:  ucmac.String(),
			BCMAC:  bcmac.String(),
			OldMAC: oldmac.String(),
			PMAC:   pmac.String(),
			PIPS:	tpips,
		},
	}
	if pips == nil || len(pips) <= 0 {  //如果pips为nil或长度小于0，则将data中的PIPS字段置为nil
		data.AddMAC.PIPS = nil
	}
	msg, _ := json.Marshal(data)  //封装成json并发送
	dpSendMsg(msg)
}

//##向代理发送删除mac地址的请求
func DPCtrlDelMAC(iface string, mac net.HardwareAddr) {
	log.WithFields(log.Fields{"mac": mac}).Debug("")

	data := DPDelMACReq{
		DelMAC: &DPDelMAC{
			Iface: iface,
			MAC:   mac.String(),
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##向代理发送刷新应用程序列表的请求
//最终，当 NeuVector 代理收到该请求后，会重新扫描集群中所有节点上运行的应用程序，并更新 NeuVector 中的应用程序列表。应用程序列表包括每个节点上正在运行的进程以及它们的元数据信息，如进程名称、命令行参数、环境变量等。这个函数的目的是确保 NeuVector 拥有最新的应用程序列表，以便它能够更准确地分析和检测集群中的网络流量。
func DPCtrlRefreshApp() {
	log.Debug("")

	data := DPRefreshAppReq{
		RefreshApp: &DPRefreshApp{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##用于向neuvector代理发送配置mac地址的请求
//MACs 表示要配置的MAC地址列表
//tap 表示是否启用TAP模式，可选，可为nil
//appMap 表示要配置的应用程序映射表，可选，可为nil

//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息配置相应的 MAC 地址，并根据需要启用 TAP 模式和应用程序映射表。TAP 模式是一种虚拟网络设备模式，用于模拟一个以太网交换机或者桥接器，从而实现对数据包的更为灵活的处理和控制。应用程序映射表用于将不同的 IP 协议和端口号映射到相应的应用程序上，在 NeuVector 进行安全性检测时可以更好地识别和过滤网络流量。
func DPCtrlConfigMAC(MACs []string, tap *bool, appMap map[share.CLUSProtoPort]*share.CLUSApp) {
	data := DPConfigMACReq{
		Cfg: &DPMacConfig{
			MACs: MACs,
		},
	}
	if tap != nil {
		data.Cfg.Tap = tap
	}
	if appMap != nil && len(appMap) > 0 {
		apps := make([]DPProtoPortApp, len(appMap))
		i := 0
		for p, app := range appMap {
			apps[i] = DPProtoPortApp{
				IPProto: p.IPProto, Port: p.Port,
				Application: app.Application,
				Server:      app.Server,
			}
			i++
		}
		data.Cfg.Apps = &apps  //将apps各元素添加到data结构体的Apps字段
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##用于向neuvector代理发送添加端口对的请求
//vex_iface 表示要添加的虚拟外部网络接口名称
//vin_iface 表示要添加的虚拟内部网络接口名称
//epmac 表示要分配给该端口对的EPMAC地址
//quar 表示是否启用隔离模式，可选，也可为nil

//虚拟外部网络接口（Virtual External Interface，简称 VEX）通常是一种面向物理网络的虚拟网络接口，它用于实现虚拟机或者容器与物理网络之间的通信。当虚拟机或者容器需要访问外部网络资源时，它们会通过 VEX 接口将数据包发送到物理网络上，并由物理交换机或路由器等设备进行转发和处理。因此，VEX 接口通常要与物理网络上的 VLAN、IP 地址、MAC 地址等相关信息相对应，以便确保其能够正确地与物理网络进行通信。
//虚拟内部网络接口（Virtual Internal Interface，简称 VIN）则是一种纯虚拟化的网络接口，它主要用于实现虚拟机或者容器之间的通信。VIN 接口通常只存在于虚拟网络中，它们可以在同一物理主机上的不同虚拟机或容器之间直接进行通信，而无需经过任何物理网络设备的转发和处理。因此，VIN 接口通常不需要与物理网络相关的信息，如 VLAN、IP 地址等。
//在 NeuVector 中，这两种接口类型常常会被用来配置和管理不同的端口对、流量转发规则等网络安全策略。

//EPMAC 是一种特殊类型的 MAC 地址，它用于标识虚拟网络中的端口对。EPMAC 的全称是 "External Port MAC"，即外部端口 MAC 地址。在虚拟网络中，每个端口对（Port Pair）都会被分配一个唯一的 EPMAC 地址，该地址用于标识该端口对的位置以及与之关联的虚拟机或者容器等资源。EPMAC 地址通常是由虚拟网络管理软件自动分配和管理的，并且不同的虚拟化平台可能采用不同的 EPMAC 分配策略。在 NeuVector 中，EPMAC 地址被用作安全性检测的重要依据，从而确保集群中的所有网络流量都能够被准确地追踪和监测。

//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息添加一个新的端口对，并将其与相应的 EPMAC 地址关联起来。如果启用隔离模式，则该端口对将被放置在一个单独的隔离网络中，以便更好地控制和监测网络流量。
func DPCtrlAddPortPair(vex_iface, vin_iface string, epmac net.HardwareAddr, quar *bool) {
	data := DPAddPortPairReq{
		AddPortPair: &DPPortPair{
			IfaceVex: vex_iface,
			IfaceVin: vin_iface,
			EPMAC:    epmac.String(),
		},
	}
	if quar != nil {
		data.AddPortPair.Quar = quar
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##用于向neuvector代理发送删除端口对的请求
func DPCtrlDelPortPair(vex_iface, vin_iface string) {
	data := DPDelPortPairReq{
		DelPortPair: &DPPortPair{
			IfaceVex: vex_iface,
			IfaceVin: vin_iface,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##用于向neuvector代理发送查询mac地址统计信息的请求
//macs 表示要查询的mac地址列表
//cb 表示回调函数，用于在neuvector返回结果后异步处理结果
//param 表示传递给回调函数的参数

//最终，当 NeuVector 代理收到该请求后，会根据请求中的 MAC 地址信息查询相应的统计信息，并将结果返回给调用方。回调函数 cb 将在 NeuVector 返回结果后被异步执行，并将查询结果作为参数传递进来，以供调用方进一步处理和分析。
func DPCtrlStatsMAC(macs []*net.HardwareAddr, cb DPCallback, param interface{}) {
	log.WithFields(log.Fields{"macs": macs}).Debug("")

	var dp_macs []string
	for _, mac := range macs {   //将macs切片中的每个mac地址转换为字符串格式
		dp_macs = append(dp_macs, mac.String())
	}

	data := DPStatsMACReq{
		Stats: &DPMACArray{MACs: dp_macs},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}


//##用于向neuvector代理发送查询代理节点统计信息的请求
//cb 表示回调函数，用于neuvector返回结果后异步处理结果
//param 表示传递给回调函数的参数
//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息查询代理节点的统计信息，并将结果返回给调用方。回调函数 cb 将在 NeuVector 返回结果后被异步执行，并将查询结果作为参数传递进来，以供调用方进一步处理和分析。
func DPCtrlStatsAgent(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPStatsAgentReq{
		Stats: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

//##用于向neuvector代理发送查询代理节点计数器信息的请求

//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息查询代理节点的计数器信息，并将结果返回给调用方。回调函数 cb 将在 NeuVector 返回结果后被异步执行，并将查询结果作为参数传递进来，以供调用方进一步处理和分析。
func DPCtrlCounterAgent(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPCounterAgentReq{
		Counter: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

//##向neuvector代理发送设置代理节点调试信息的请求
//用于设置代理节点调试信息的函数，可以方便地对代理节点进行调试和排查问题。
func DPCtrlConfigAgent(debug *DPDebug) {
	log.Debug("")

	data := DPSetDebugReq{
		Debug: debug,
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##用于向 NeuVector 代理发送查询会话数量统计信息的请求。
//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息查询会话数量的统计信息，并将结果返回给调用方。回调函数 cb 将在 NeuVector 返回结果后被异步执行，并将查询结果作为参数传递进来，以供调用方进一步处理和分析。
func DPCtrlCountSession(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPCountSessionReq{
		CountSession: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

//##用于向 NeuVector 代理发送查询会话列表的请求。
//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息查询会话列表，并将结果返回给调用方。回调函数 cb 将在 NeuVector 返回结果后被异步执行，并将查询结果作为参数传递进来，以供调用方进一步处理和分析。
func DPCtrlListSession(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPListSessionReq{
		ListSession: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

//##向 NeuVector 代理发送清除指定会话信息的请求。
//这个函数是用于清除指定会话信息的函数，可以方便地对会话信息进行管理和维护。
func DPCtrlClearSession(id uint32) {
	log.Debug("")

	data := DPClearSessionReq{
		ClearSession: &DPClearSession{
			ID: id,
		},
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}


//##向neuvector代理发送查询计量信息的请求
//最终，当 NeuVector 代理收到该请求后，会根据请求中的信息查询计量信息，并将结果返回给调用方。回调函数 cb 将在 NeuVector 返回结果后被异步执行，并将查询结果作为参数传递进来，以供调用方进一步处理和分析。
/*
计量信息是指在 NeuVector 中，用于收集和统计网络流量、事件、安全威胁等各种数据的一类信息。它可以帮助用户了解系统的性能、安全状况和异常情况，并且提供给用户更加详细和准确的分析工具和报告。计量信息通常包括以下几个方面：
流量统计：NeuVector 可以对网络流量进行统计和分类，以了解每个容器之间的流量模式和传输速率。
事件日志：NeuVector 可以记录和存储各种事件，如攻击尝试、漏洞扫描、不寻常的行为等，以便后续审计和调查。
安全指标：NeuVector 可以通过各种方式（如 CVE 数据库、漏洞扫描器等）对容器镜像和运行时进行风险评估，以发现可能存在的安全问题。
性能指标：NeuVector 可以收集和展示各种性能指标，如 CPU 利用率、内存使用情况、网络延迟等，以帮助用户优化系统资源和应用程序性能。
*/
func DPCtrlListMeter(cb DPCallback, param interface{}) {
	log.Debug("")

	data := DPListMeterReq{
		ListMeter: &DPEmpty{},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgEx(msg, 5, cb, param)
}

//##获取neuvector控制通道客户端的地址
//const dpClient string = "/tmp/dp_client.%d" 

/*
这里的控制通道指的是 NeuVector 容器安全平台中的一种通信方式，用于在容器和宿主机之间进行双向的命令和数据交换。这个控制通道实现了一个客户端-服务器模型，其中 NeuVector 控制通道客户端运行在每个容器内部，而 NeuVector 控制通道服务器则运行在宿主机上。

通过控制通道，NeuVector 控制通道客户端和服务器可以进行各种操作，如启动和停止容器、查询计量信息、发送安全事件等等。在实现上，控制通道使用 Unix 域套接字（Unix domain socket）技术来实现，这种套接字只能在本地进程间进行通信，因此具有较高的安全性和隔离性。

总的来说，控制通道是 NeuVector 容器安全平台中一个重要的组件，它可以帮助用户进行容器管理、安全扫描、风险评估等各种操作，提供给用户更多的可视化信息和安全保障。
*/
func getDPCtrlClientAddr() string {
	return fmt.Sprintf(dpClient, os.Getpid())
}

const maxMsgSize int = 8120

//##用于向neuvector代理发送配置工作负载IP策略的请求
//policy 表示要配置的工作负载IP策略
//cmd 表示策略的命令码
func DPCtrlConfigPolicy(policy *DPWorkloadIPPolicy, cmd uint) int {
	var start, end int = 0, 0  //起始位置
	var first bool = true   
	var rulesPerMsg int = 40  //每条消息包含的规则数

	num := len(policy.IPRules)   //策略数量
	log.WithFields(log.Fields{
		"workload": policy.WlID, "mac": policy.WorkloadMac, "num": num,
	}).Debug("")

	for num > 0 || first == true {   //循环发送每组规则
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= rulesPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + rulesPerMsg
		}
		data := DPPolicyCfgReq{
			DPPolicyCfg: &DPPolicyCfg{
				Cmd:         cmd,
				Flag:        flag,
				DefAction:   policy.DefAction,
				ApplyDir:    policy.ApplyDir,
				WorkloadMac: policy.WorkloadMac,
				IPRules:     policy.IPRules[start:end],
			},
		}
		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newRulesPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newRulesPerMsg == rulesPerMsg {
				newRulesPerMsg--
			}
			if newRulesPerMsg == 0 {
				log.WithFields(log.Fields{
					"rule": policy.IPRules[start]},
				).Error("rule too large")
				return -1
			}
			rulesPerMsg = newRulesPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			return -1
		}
		num = num + start - end
		start = end
		first = false
	}
	return 0
}

//##用于向 NeuVector 代理发送删除 FQDN 的请求。
/*
FQDN 是 Fully Qualified Domain Name 的缩写，中文意思是“完全限定域名”。它是一个互联网上用来唯一标识某个主机的名称。FQDN 通常由三部分组成：
主机名（hostname）：指该主机自己取的名字，如 www、mail、ftp 等。
域名（domain name）：指该主机所属的域名，如 google.com、baidu.cn 等。
顶级域名（top-level domain）：指域名的最后一部分，如 .com、.edu、.gov 等。
例如，在 www.google.com 这个 FQDN 中，www 是主机名，google 是域名，.com 是顶级域名。
FQDN 在互联网上起到了重要的作用，它可以将多个主机和服务组合在一起，形成一个逻辑上的网络系统，并通过 DNS 解析实现了可靠的命名和寻址机制。
在 NeuVector 容器安全平台中，FQDN 通常被用于描述容器之间的通信，或者用于访问外部网络资源。例如，用户可以使用 FQDN 配置工作负载 IP 策略，从而控制特定 FQDN 的数据流向和数据访问。
*/
func DPCtrlDeleteFqdn(names []string) int {
	var start, end int = 0, len(names)
	var namesPerMsg int = 20
	var req *DPFqdnDeleteReq

	for start < end {
		if start+namesPerMsg < end {
			req = &DPFqdnDeleteReq{Delete: &DPFqdnList{Names: names[start : start+namesPerMsg]}}
		} else {
			req = &DPFqdnDeleteReq{Delete: &DPFqdnList{Names: names[start:end]}}
		}
		start = start + namesPerMsg
		msg, _ := json.Marshal(req)
		if dpSendMsg(msg) < 0 {
			return -1
		}
	}
	return 0
}

//##用于向neuvector代理发送设置FQDN对应IP地址的请求
//fqdnip  表示要设置的FQDN和其对应的IP地址列表
func DPCtrlSetFqdnIp(fqdnip *share.CLUSFqdnIp) int {
	fips := make([]net.IP, 0, len(fqdnip.FqdnIP))
	for _, fip := range fqdnip.FqdnIP {  //遍历fqdnip.FqdnIP列表中的所有IP地址
		if utils.IsIPv4(fip) == false {
			continue
		}
		fips = append(fips, fip)  //将IP地址存在fips中
	}
	data := DPFqdnIpSetReq {
		Fqdns: &DPFqdnIps{
			FqdnName:    fqdnip.FqdnName,
			FqdnIps:     fips,
		},
	}
	msg, _ := json.Marshal(data)
	if dpSendMsg(msg) < 0 {
		return -1
	}
	return 0
}


//##用于向neuvector代理发送配置策略地址的请求（分批发送，类似getDPCtrlClientAddr函数）
//subnets 表示要配置的子网列表
func DPCtrlConfigPolicyAddr(subnets map[string]share.CLUSSubnet) {
	data_subnet := make([]DPSubnet, 0, len(subnets))
	for _, addr := range subnets {
		if utils.IsIPv4(addr.Subnet.IP) == false {
			continue
		}
		subnet := DPSubnet{
			IP:   addr.Subnet.IP,
			Mask: net.IP(addr.Subnet.Mask),
		}
		data_subnet = append(data_subnet, subnet)
	}

	var start, end int = 0, 0
	var first bool = true
	var subnetPerMsg int = 600
	var msg []byte

	num := len(data_subnet)
	log.WithFields(log.Fields{"policy_address_num": num}).Debug("config policy address")

	for num > 0 || first == true {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= subnetPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + subnetPerMsg
		}
		data := DPPolicyAddressCfgReq{
			PolicyAddrCfg: &DPInternalSubnetCfg{
				Flag:    flag,
				Subnets: data_subnet[start:end],
			},
		}

		msg, _ = json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newSubnetPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newSubnetPerMsg == subnetPerMsg {
				newSubnetPerMsg--
			}
			if newSubnetPerMsg == 0 {
				log.WithFields(log.Fields{"policy_address": data_subnet[start]}).Error("policy address too large")
				return
			}
			subnetPerMsg = newSubnetPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return
		}
		num = num + start - end
		start = end
		first = false
	}
}

//##用于向 NeuVector 代理发送配置内部子网的请求。
//subnets 表示要配置的内部子网列表
func DPCtrlConfigInternalSubnet(subnets map[string]share.CLUSSubnet) {
	data_subnet := make([]DPSubnet, 0, len(subnets))
	for _, addr := range subnets {
		if utils.IsIPv4(addr.Subnet.IP) == false {
			continue
		}
		subnet := DPSubnet{
			IP:   addr.Subnet.IP,
			Mask: net.IP(addr.Subnet.Mask),
		}
		data_subnet = append(data_subnet, subnet)
	}

	var start, end int = 0, 0
	var first bool = true
	var subnetPerMsg int = 600
	var msg []byte

	num := len(data_subnet)
	log.WithFields(log.Fields{"internal_subnet_num": num}).Debug("config internal subnet")

	for num > 0 || first == true {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= subnetPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + subnetPerMsg
		}
		data := DPInternalSubnetCfgReq{
			SubnetCfg: &DPInternalSubnetCfg{
				Flag:    flag,
				Subnets: data_subnet[start:end],
			},
		}

		msg, _ = json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newSubnetPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newSubnetPerMsg == subnetPerMsg {
				newSubnetPerMsg--
			}
			if newSubnetPerMsg == 0 {
				log.WithFields(log.Fields{"internal_subnet": data_subnet[start]}).Error("internal subnet too large")
				return
			}
			subnetPerMsg = newSubnetPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return
		}
		num = num + start - end
		start = end
		first = false
	}
}

//##用于向 NeuVector 代理发送配置特殊 IP 子网的请求。
//subnets 表示要配置的特殊IP子网列表
func DPCtrlConfigSpecialIPSubnet(subnets map[string]share.CLUSSpecSubnet) {
	data_subnet := make([]DPSpecSubnet, 0, len(subnets))
	for _, addr := range subnets {
		if utils.IsIPv4(addr.Subnet.IP) == false {
			continue
		}
		subnet := DPSpecSubnet{
			IP:     addr.Subnet.IP,
			Mask:   net.IP(addr.Subnet.Mask),
			IpType: addr.IpType,
		}
		data_subnet = append(data_subnet, subnet)
	}

	var start, end int = 0, 0
	var first bool = true
	var subnetPerMsg int = 600

	num := len(data_subnet)
	log.WithFields(log.Fields{"special_net_num": num}).Debug("config special subnet")

	for num > 0 || first == true {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= subnetPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + subnetPerMsg
		}
		data := DPSpecialIPSubnetCfgReq{
			SubnetCfg: &DPSpecIPSubnetCfg{
				Flag:    flag,
				Subnets: data_subnet[start:end],
			},
		}

		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newSubnetPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newSubnetPerMsg == subnetPerMsg {
				newSubnetPerMsg--
			}
			if newSubnetPerMsg == 0 {
				log.WithFields(log.Fields{"specialIP_subnet": data_subnet[start]}).Error("special subnet too large")
				return
			}
			subnetPerMsg = newSubnetPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return
		}
		num = num + start - end
		start = end
		first = false
	}
}

//##用于向neuvector代理发送配置数据防泄漏（DLP）规则的请求，将大量的规则配置消息分配发送
//wldlprule 表示要配置的DLP规则信息
func DPCtrlConfigDlp(wldlprule *DPWorkloadDlpRule) int {
	var start, end int = 0, 0
	var start1, end1 int = 0, 0
	var first bool = true
	var rulesPerMsg int = 40

	num := len(wldlprule.DlpRuleNames)
	num1 := len(wldlprule.WafRuleNames)
	total := num + num1
	log.WithFields(log.Fields{
		"workload": wldlprule.WlID, "mac": wldlprule.WorkloadMac,
		"policyids": wldlprule.PolicyRuleIds,
		"polwafids": wldlprule.PolWafRuleIds,
		"dlprulenum": num,
		"wafrulenum": num1,
		"total": total,
	}).Debug("config dlp")

	for total > 0 || first == true {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if total <= rulesPerMsg {
			flag |= C.MSG_END
			end = start + num
			end1 = start1 + num1
		} else {
			tlen := rulesPerMsg/2
			if num <= tlen {
				end = start + num
				if num1 > (rulesPerMsg - num) {
					end1 = start1 + (rulesPerMsg - num)
				} else {
					end1 = start1 + num1
				}
			} else {
				end = start + tlen
				if num1 > (rulesPerMsg - tlen) {
					end1 = start1 + (rulesPerMsg - tlen)
				} else {
					end1 = start1 + num1
				}
			}
		}
		data := DPDlpCfgReq{
			DPWlDlpCfg: &DPDlpCfg{
				Flag:         flag,
				WorkloadMac:  wldlprule.WorkloadMac,
				DlpRuleNames: make([]*DPDlpRidSetting, 0),
				WafRuleNames: make([]*DPDlpRidSetting, 0),
				RuleIds:      wldlprule.PolicyRuleIds,
				WafRuleIds:   wldlprule.PolWafRuleIds,
				RuleType:     wldlprule.RuleType,
				WafRuleType:  wldlprule.WafRuleType,
			},
		}
		for _, drn := range wldlprule.DlpRuleNames[start:end] {
			drids := &DPDlpRidSetting{
				ID:     drn.ID,
				Action: drn.Action,
			}
			data.DPWlDlpCfg.DlpRuleNames = append(data.DPWlDlpCfg.DlpRuleNames, drids)   //解析出dlp规则的名称
		}
		for _, wrn := range wldlprule.WafRuleNames[start1:end1] {
			wrids := &DPDlpRidSetting{
				ID:     wrn.ID,
				Action: wrn.Action,
			}
			data.DPWlDlpCfg.WafRuleNames = append(data.DPWlDlpCfg.WafRuleNames, wrids) //解析出waf规则的名称
		}
		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newRulesPerMsg := maxMsgSize / (sz/((end-start)+(end1-start1)) + 1)
			if newRulesPerMsg == rulesPerMsg {
				newRulesPerMsg--
			}
			if newRulesPerMsg == 0 {
				log.WithFields(log.Fields{
					"DlpRuleNames": wldlprule.DlpRuleNames[start],
					"WafRuleNames": wldlprule.WafRuleNames[start1]},
				).Error("rulenames too large")
				return -1
			}
			rulesPerMsg = newRulesPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			log.Debug("dpSendMsg error")
			return -1
		}
		num = num + start - end
		start = end
		num1 = num1 + start1 - end1
		start1 = end1
		total = num + num1
		first = false
	}
	return 0
}

//##用于向 NeuVector 代理发送构建数据防泄漏（DLP）规则的请求。
//dlpRulesInfo 表示DLP规则的信息
//dlpDpMacs 表示要应用规则的工作负载MAC地址集合
//delmacs 表示要删除规则的工作负载MAC地址集合
/*
dlpApplyDir 表示DLP 规则的应用方向，指定了规则检查数据流的方向
DP_DLP_APPLY_DIR_BOTH（0）：表示检查双向数据流。
DP_DLP_APPLY_DIR_INGRESS（1）：表示只检查入站数据流。
DP_DLP_APPLY_DIR_EGRESS（2）：表示只检查出站数据流。
*/
func DPCtrlBldDlp(dlpRulesInfo []*DPDlpRuleEntry, dlpDpMacs utils.Set, delmacs utils.Set, dlpApplyDir int) int {
	var start, end int = 0, 0
	var first bool = true
	var rulesPerMsg int = 40

	num := len(dlpRulesInfo)
	macNum := dlpDpMacs.Cardinality()
	delmacNum := 0
	if delmacs != nil {
		delmacNum = delmacs.Cardinality()
	}
	log.WithFields(log.Fields{
		"dlpRuleNum": num, "macNum": macNum, "delmacNum": delmacNum,
	}).Debug("build dlp")

	for num > 0 || first == true {
		var flag uint = 0

	retry:
		flag = 0
		if start == 0 {
			flag = C.MSG_START
		}
		if num <= rulesPerMsg {
			flag |= C.MSG_END
			end = start + num
		} else {
			end = start + rulesPerMsg
		}
		data := DPDlpBldReq{
			DPDlpBld: &DPDlpBuild{
				Flag:        flag,
				ApplyDir:    dlpApplyDir,
				DlpRules:    dlpRulesInfo[start:end],
				WorkloadMac: make([]string, 0),
				DelMac:      make([]string, 0),
			},
		}
		for mc := range dlpDpMacs.Iter() {
			data.DPDlpBld.WorkloadMac = append(data.DPDlpBld.WorkloadMac, mc.(string))
		}
		if delmacs != nil {
			for dmc := range delmacs.Iter() {
				data.DPDlpBld.DelMac = append(data.DPDlpBld.DelMac, dmc.(string))
			}
		}
		msg, _ := json.Marshal(data)
		sz := len(msg)
		if sz > maxMsgSize {
			// a very rough way to calculate rulesPerMsg
			newRulesPerMsg := maxMsgSize / (sz/(end-start) + 1)
			if newRulesPerMsg == rulesPerMsg {
				newRulesPerMsg--
			}
			if newRulesPerMsg == 0 {
				log.WithFields(log.Fields{
					"DlpRules": dlpRulesInfo[start]},
				).Error("rules too large")
				return -1
			}
			rulesPerMsg = newRulesPerMsg
			goto retry
		}

		if dpSendMsg(msg) == -1 {
			return -1
		}
		num = num + start - end
		start = end
		first = false
	}
	return 0
}

//##用于向 NeuVector 代理发送更改数据防泄漏（DLP）规则工作负载 MAC 地址的请求。
//oldmacs 表示要更改的原始工作负载MAC地址集合
//addmacs 表示新增加的工作负载mac地址集合
//delmacs 表示要删除的工作负载mac地址集合

//当 NeuVector 代理收到这个消息后，会根据其中的内容更新 DLP 规则应用的工作负载 MAC 地址列表，以便在下一次检查时使用最新的列表。
//总的来说，DPCtrlBldDlpChgMac() 函数是用于更改 DLP 规则工作负载 MAC 地址的函数，它通过向 NeuVector 代理发送请求，实现了在运行时动态修改工作负载列表的功能。
func DPCtrlBldDlpChgMac(oldmacs, addmacs, delmacs utils.Set) {

	data := DPDlpBldMACReq{
		DPDlpChgBldMac: &DPDlpBldMac{
			OldMac: make([]string, 0),
			AddMac: make([]string, 0),
			DelMac: make([]string, 0),
		},
	}
	for omac := range oldmacs.Iter() {
		data.DPDlpChgBldMac.OldMac = append(data.DPDlpChgBldMac.OldMac, omac.(string))
	}
	for amac := range addmacs.Iter() {
		data.DPDlpChgBldMac.AddMac = append(data.DPDlpChgBldMac.AddMac, amac.(string))
	}
	for dmac := range delmacs.Iter() {
		data.DPDlpChgBldMac.DelMac = append(data.DPDlpChgBldMac.DelMac, dmac.(string))
	}
	msg, _ := json.Marshal(data)
	dpSendMsg(msg)
}

//##用于向 NeuVector 代理发送更改数据防泄漏（DLP）规则配置的工作负载 MAC 地址的请求。

func DPCtrlDlpCfgChgMac(delmacs utils.Set) {

	data := DPDlpCfgMACReq{
		DPDlpChgCfgMac: &DPDlpCfgMac{
			DelMac: make([]string, 0),
		},
	}
	for dmac := range delmacs.Iter() {
		data.DPDlpChgCfgMac.DelMac = append(data.DPDlpChgCfgMac.DelMac, dmac.(string))
	}
	msg, _ := json.Marshal(data)
	if dpSendMsg(msg) == -1 {
		log.Debug("dpSendMsg send error")
	}
}

// --- keep alive

//##用作 NeuVector 代理和数据平面之间心跳包（keep-alive）的回调函数，在接收到心跳包响应时被调用
//buf 表示收到的心跳包消息
//param 表示用户自定义的参数
func cbKeepAlive(buf []byte, param interface{}) bool {
	if len(buf) == 0 {
		log.Error("Empty message, close dp socket")
		closeDP()
		return true
	}

	hdr := ParseDPMsgHeader(buf)   //解析收到的消息头
	if hdr == nil {
		log.Error("Invalid DP message header")
		return false
	} else if hdr.Kind != C.DP_KIND_KEEP_ALIVE {  //判断消息是否为心跳包响应
		// Keep waiting
		log.Error("Not keep-alive message")
		return false
	}

	var received uint32
	offset := int(unsafe.Sizeof(*hdr))
	r := bytes.NewReader(buf[offset:])
	binary.Read(r, binary.BigEndian, &received)   //获取收到的序列号

	if received == keepAliveSeq {  //比较序列号是否与期望值一致
		// Matched response
		return true    //表示 NeuVector 代理和数据平面之间的连接正常，返回 true 表示成功处理了心跳包响应
	}

	// Keep waiting
	log.WithFields(log.Fields{
		"len": len(buf), "expect": keepAliveSeq, "received": received,
	}).Error("Receive mismatched reply")
	return false    //函数会返回 false，表示需要继续等待下一个心跳包响应。
}

func dpKeepAlive() {
	keepAliveSeq++
	seq := keepAliveSeq
	data := DPKeepAliveReq{
		Alive: &DPKeepAlive{SeqNum: seq},
	}
	msg, _ := json.Marshal(data)
	dpSendMsgExSilent(msg, 3, cbKeepAlive, &seq)
}

func monitorDP() {
	dpTicker := time.Tick(dpKeepAliveInterval)
	dpConnJamRetry := 0

	for {
		select {
		case <-dpTicker:
			// Connect to DP if not; keep alive is connected.
			if dpConn == nil {
				if dpConnJamRetry > dpConnJamRetryMax {
					log.WithFields(log.Fields{"retry": dpConnJamRetry}).Error("dp socket congestion.")
					// log.WithFields(log.Fields{"retry": dpConnJamRetry}).Error("dp socket congestion. Exit!")
					// restartChan <- nil
					// break
				}

				log.WithFields(log.Fields{"retry": dpConnJamRetry}).Info("Connecting to DP socket ...")
				newConn := connectDP()
				if newConn != nil {
					dpClientLock()
					dpConn = newConn
					// align msg with DP using keep alive
					dpKeepAlive()
					dpClientUnlock()

					if dpConn != nil {
						log.Info("DP Connected")
						dpConnJamRetry = 0
						statusChan <- true
					} else {
						// This is to detect communication socket congestion, so only increment when
						// connection is made.
						dpConnJamRetry++
					}
				} else {
					dpConnJamRetry = 0
				}
			} else if dpAliveMsgCnt == 0 {
				// Only a best effort to avoid unecessary keep alive.
				dpClientLock()
				dpKeepAlive()
				dpClientUnlock()

				// Cannot send notify in closeDP() as it holds dpClientMutex, at the same time docker
				// goroutine can send dp message but cannot get the mutex -> deadlock
				if dpConn == nil {
					statusChan <- false
				}
			} else {
				dpAliveMsgCnt = 0
			}
		}
	}
}

func connectDP() *net.UnixConn {
	var conn *net.UnixConn
	var err error
	kind := "unixgram"
	lpath := getDPCtrlClientAddr()
	laddr := net.UnixAddr{lpath, kind}
	raddr := net.UnixAddr{DPServer, kind}

	conn, err = net.DialUnix(kind, &laddr, &raddr)
	if err != nil {
		os.Remove(lpath)
		return nil
	} else {
		return conn
	}
}

func closeDP() {
	if dpConn != nil {
		log.Info("DP Closed")
		dpConn.Close()
		dpConn = nil
	}
	os.Remove(getDPCtrlClientAddr())
}

func Open(cb DPTaskCallback, sc chan bool, ec chan interface{}) {
	log.Info("")

	taskCallback = cb
	statusChan = sc
	restartChan = ec

	go listenDP()
	go monitorDP()
}

func Close() {
	log.Info("")
	closeDP()
}

func Connected() bool {
	return (dpConn != nil)
}
