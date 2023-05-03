package dp

// #include "../../defs.h"
import "C"

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"net"
	"os"
	"syscall"   //提供了底层系统调用相关的函数和类型定义，例如 Socket、Connect、Sendto、Recvfrom 等。可以用于实现底层的网络通信、进程管理等操作。
	"time"   //提供了时间相关的函数和类型定义，例如 Time、Now、Sleep 等。可以用于计时、延迟执行、获取当前时间等操作。
	"unsafe"  //提供了与指针和内存相关的函数和类型定义，例如 Pointer、Sizeof、Offsetof 等。可以用于进行底层的内存操作和转换，例如将数据类型转换为字节序列并进行强制类型转换。

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

//##用于解析 DP 数据包中应用程序信息的函数。
//msg 表示需要解析的DP数据包
func dpMsgAppUpdate(msg []byte) {
	var appHdr C.DPMsgAppHdr   //表示DP应用程序消息头部，保存了MAX地址和端口数等基本信息
	var app C.DPMsgApp        //表示DP应用程序消息内容，保存了应用程序的详细信息，如协议号、服务类型、应用程序ID等

	// Verify header length
	appHdrLen := int(unsafe.Sizeof(appHdr))
	if len(msg) < appHdrLen {
		log.WithFields(log.Fields{"expect": appHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	binary.Read(r, binary.BigEndian, &appHdr)  //对msg进行读取

	// Verify total length
	ports := int(appHdr.Ports)
	totalLen := appHdrLen + int(unsafe.Sizeof(app))*ports
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"ports": ports, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return
	}

	mac := net.HardwareAddr(C.GoBytes(unsafe.Pointer(&appHdr.MAC[0]), 6))
	apps := make(map[share.CLUSProtoPort]*share.CLUSApp)

	for i := 0; i < ports; i++ {
		binary.Read(r, binary.BigEndian, &app)
		p := share.CLUSProtoPort{
			Port:    uint16(app.Port),
			IPProto: uint8(app.IPProto),
		}
		apps[p] = &share.CLUSApp{  //将读取的详细信息存储在名为apps的map类型变量中
			CLUSProtoPort: p,
			Proto:         uint32(app.Proto),
			Server:        uint32(app.Server),
			Application:   uint32(app.Application),
		}
	}

	task := DPTask{Task: DP_TASK_APPLICATION, MAC: mac, Apps: apps}  //创建了一个 DPTask 类型的变量 task，并将其填充为 DP_TASK_APPLICATION 类型的任务，并将 mac 和 apps 存储在 task 中
	taskCallback(&task)  //调用之前设置的全局回调函数 taskCallback，并传递 task 变量作为参数，以执行相应的任务处理逻辑。
}


//##用于解析 DP 数据包中威胁日志信息的函数
//msg 表示需要解析的DP数据包
func dpMsgThreatLog(msg []byte) {
	var tlog C.DPMsgThreatLog   //表示 DP 威胁日志消息的内容

	r := bytes.NewReader(msg)
	binary.Read(r, binary.BigEndian, &tlog)  //读取msg和解析

	jlog := share.CLUSThreatLog{
		ID:          utils.GetTimeUUID(time.Now().UTC()),   //表示威胁日志的唯一标识符，使用 utils.GetTimeUUID 函数生成一个新的 UUID。
		ThreatID:    uint32(tlog.ThreatID),  //表示威胁 ID，其值等于 tlog.ThreatID。
		Count:       uint32(tlog.Count),   //表示触发次数，其值等于 tlog.Count。
		Action:      uint8(tlog.Action),   //表示威胁的动作，例如阻止、允许、告警等，其值等于 tlog.Action。
		Severity:    uint8(tlog.Severity),   //表示威胁的严重程度，其值等于 tlog.Severity。
		EtherType:   uint16(tlog.EtherType),   //表示以太网帧中的协议类型，例如 IPv4、IPv6 等，其值等于 tlog.EtherType。
		IPProto:     uint8(tlog.IPProto),    //表示 IP 协议类型，例如 TCP、UDP、ICMP 等，其值等于 tlog.IPProto。
		Application: uint32(tlog.Application),   //表示应用程序 ID，其值等于 tlog.Application。
		CapLen:      uint16(tlog.CapLen),   //表示抓包数据的长度，其值等于 tlog.CapLen。
	}

	jlog.ReportedAt = time.Unix(int64(tlog.ReportedAt), 0).UTC()

	if (tlog.Flags & C.DPLOG_FLAG_PKT_INGRESS) != 0 {
		jlog.PktIngress = true
	}
	if (tlog.Flags & C.DPLOG_FLAG_SESS_INGRESS) != 0 {
		jlog.SessIngress = true
	}
	if (tlog.Flags & C.DPLOG_FLAG_TAP) != 0 {
		jlog.Tap = true
	}
	EPMAC := net.HardwareAddr(C.GoBytes(unsafe.Pointer(&tlog.EPMAC[0]), 6))
	switch jlog.EtherType {
	case syscall.ETH_P_IP:
		jlog.SrcIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.SrcIP[0]), 4))
		jlog.DstIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.DstIP[0]), 4))
	case syscall.ETH_P_IPV6:
		jlog.SrcIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.SrcIP[0]), 16))
		jlog.DstIP = net.IP(C.GoBytes(unsafe.Pointer(&tlog.DstIP[0]), 16))
	}
	switch jlog.IPProto {
	case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
		jlog.SrcPort = uint16(tlog.SrcPort)
		jlog.DstPort = uint16(tlog.DstPort)
	case syscall.IPPROTO_ICMP, syscall.IPPROTO_ICMPV6:
		jlog.ICMPCode = uint8(tlog.ICMPCode)
		jlog.ICMPType = uint8(tlog.ICMPType)
	}
	jlog.Msg = C.GoString(&tlog.Msg[0])

	log.WithFields(log.Fields{"log": jlog}).Debug("")

	pkt := C.GoBytes(unsafe.Pointer(&tlog.Packet[0]), C.int(tlog.PktLen))
	jlog.Packet = base64.StdEncoding.EncodeToString(pkt)

	task := DPTask{Task: DP_TASK_THREAT_LOG, SecLog: &jlog, MAC: EPMAC}
	taskCallback(&task)
}

func dpMsgConnection(msg []byte) {
	var connHdr C.DPMsgConnectHdr
	var conn C.DPMsgConnect

	// Verify header length
	connHdrLen := int(unsafe.Sizeof(connHdr))
	if len(msg) < connHdrLen {
		log.WithFields(log.Fields{"expect": connHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	binary.Read(r, binary.BigEndian, &connHdr)

	// Verify total length
	count := int(connHdr.Connects)
	totalLen := connHdrLen + int(unsafe.Sizeof(conn))*count
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"connects": count, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return
	}

	conns := make([]*ConnectionData, count)

	for i := 0; i < count; i++ {
		binary.Read(r, binary.BigEndian, &conn)

		cc := &Connection{
			ServerPort:   uint16(conn.ServerPort),
			ClientPort:   uint16(conn.ClientPort),
			IPProto:      uint8(conn.IPProto),
			Bytes:        uint64(conn.Bytes),
			Sessions:     uint32(conn.Sessions),
			FirstSeenAt:  uint32(conn.FirstSeenAt),
			LastSeenAt:   uint32(conn.LastSeenAt),
			ThreatID:     uint32(conn.ThreatID),
			Severity:     uint8(conn.Severity),
			PolicyAction: uint8(conn.PolicyAction),
			Application:  uint32(conn.Application),
			PolicyId:     uint32(conn.PolicyId),
			Violates:     uint32(conn.Violates),
		}
		switch uint16(conn.EtherType) {
		case syscall.ETH_P_IP:
			cc.ClientIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ClientIP[0]), 4))
			cc.ServerIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ServerIP[0]), 4))
		case syscall.ETH_P_IPV6:
			cc.ClientIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ClientIP[0]), 16))
			cc.ServerIP = net.IP(C.GoBytes(unsafe.Pointer(&conn.ServerIP[0]), 16))
		}
		if (conn.Flags & C.DPCONN_FLAG_INGRESS) != 0 {
			cc.Ingress = true
		}
		if (conn.Flags & C.DPCONN_FLAG_EXTERNAL) != 0 {
			// Peer that is not on the host or container's subnet
			cc.ExternalPeer = true
		}
		if (conn.Flags & C.DPCONN_FLAG_XFF) != 0 {
			// connection is xff induced
			cc.Xff = true
		}
		if (conn.Flags & C.DPCONN_FLAG_SVC_EXTIP) != 0 {
			// connection has client->svcExtIP violation
			cc.SvcExtIP = true
		}
		if (conn.Flags & C.DPCONN_FLAG_MESH_TO_SVR) != 0 {
			// appcontainer to sidecar connection has
			// client to remote svr detection
			cc.MeshToSvr = true
		}
		if (conn.Flags & C.DPCONN_FLAG_LINK_LOCAL) != 0 {
			// link local 169.254.0.0 is special svc loopback
			// used by cilium CNI
			cc.LinkLocal = true
		}

		conns[i] = &ConnectionData{
			EPMAC: net.HardwareAddr(C.GoBytes(unsafe.Pointer(&conn.EPMAC[0]), 6)),
			Conn:  cc,
		}
	}

	task := DPTask{Task: DP_TASK_CONNECTION, Connects: conns}
	taskCallback(&task)
}

func dpMsgFqdnIpUpdate(msg []byte) {
	var fqdnIpHdr C.DPMsgFqdnIpHdr
	var fqdnIp C.DPMsgFqdnIp
	// Verify header length
	fqdnIpHdrLen := int(unsafe.Sizeof(fqdnIpHdr))
	if len(msg) < fqdnIpHdrLen {
		log.WithFields(log.Fields{"expect": fqdnIpHdrLen, "actual": len(msg)}).Error("Short header")
		return
	}

	r := bytes.NewReader(msg)
	binary.Read(r, binary.BigEndian, &fqdnIpHdr)

	// Verify total length
	ipcnt := int(fqdnIpHdr.IpCnt)
	totalLen := fqdnIpHdrLen + int(unsafe.Sizeof(fqdnIp))*ipcnt
	if len(msg) != totalLen {
		log.WithFields(log.Fields{
			"ipcnt": ipcnt, "expect": totalLen, "actual": len(msg),
		}).Error("Wrong message length.")
		return
	}

	fqdns := &share.CLUSFqdnIp{
		FqdnIP: make([]net.IP, 0),
	}

	fqdns.FqdnName = C.GoString(&fqdnIpHdr.FqdnName[0])

	for i := 0; i < ipcnt; i++ {
		binary.Read(r, binary.BigEndian, &fqdnIp)
		fqdns.FqdnIP = append(fqdns.FqdnIP, net.IP(C.GoBytes(unsafe.Pointer(&fqdnIp.FqdnIP[0]), 4)))
	}
	log.WithFields(log.Fields{"fqdns": fqdns}).Debug("")

	task := DPTask{Task: DP_TASK_FQDN_IP, Fqdns: fqdns}
	taskCallback(&task)
}

func ParseDPMsgHeader(msg []byte) *C.DPMsgHdr {
	var hdr C.DPMsgHdr

	hdrLen := int(unsafe.Sizeof(hdr))
	if len(msg) < hdrLen {
		log.WithFields(log.Fields{"len": len(msg)}).Error("Short header")
		return nil
	}

	r := bytes.NewReader(msg)
	binary.Read(r, binary.BigEndian, &hdr)
	if int(hdr.Length) != len(msg) {
		log.WithFields(log.Fields{
			"kind": hdr.Kind, "expect": hdr.Length, "actual": len(msg),
		}).Error("Wrong message length.")
		return nil
	}

	return &hdr
}

func dpMessenger(msg []byte) {
	hdr := ParseDPMsgHeader(msg)
	if hdr == nil {
		return
	}

	offset := int(unsafe.Sizeof(*hdr))
	switch int(hdr.Kind) {
	case C.DP_KIND_APP_UPDATE:
		dpMsgAppUpdate(msg[offset:])
	case C.DP_KIND_THREAT_LOG:
		dpMsgThreatLog(msg[offset:])
	case C.DP_KIND_CONNECTION:
		dpMsgConnection(msg[offset:])
	case C.DP_KIND_FQDN_UPDATE:
		dpMsgFqdnIpUpdate(msg[offset:])
	}
}

func listenDP() {
	log.Debug("Listening to CTRL socket ...")

	os.Remove(ctrlServer)

	var conn *net.UnixConn
	kind := "unixgram"
	addr := net.UnixAddr{ctrlServer, kind}
	defer os.Remove(ctrlServer)
	conn, _ = net.ListenUnixgram(kind, &addr)
	defer conn.Close()

	for {
		var buf [C.DP_MSG_SIZE]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			log.WithFields(log.Fields{"error": err}).Error("Read message error.")
		} else {
			dpAliveMsgCnt++
			dpMessenger(buf[:n])
		}
	}
}

/*
这段代码是Go语言的一个dp包，它包含了三个处理函数：dpMsgAppUpdate、dpMsgThreatLog和dpMsgConnection。这三个函数都会接收一个字节数组参数，然后将其解析并作出相应的处理。

dpMsgAppUpdate函数会将字节数组转换成一个应用程序结构体，该结构体包含应用程序的各种信息。然后它会将这些信息封装到一个名为DPTask的结构体中，并调用taskCallback函数，
将这个结构体传递给该函数进行处理。

dpMsgThreatLog函数也会将字节数组转换成一个威胁日志结构体，该结构体包含威胁日志的各种信息。然后它会将这些信息封装到一个名为DPTask的结构体中，并调用taskCallback函数，
将这个结构体传递给该函数进行处理。

dpMsgConnection函数也是类似的，它会将字节数组转换成一个连接结构体，该结构体包含连接的各种信息。然后它会将这些信息封装到一个名为DPTask的结构体中，并调用taskCallback函数，
将这个结构体传递给该函数进行处理。

*/
