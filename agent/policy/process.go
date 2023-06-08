package policy

// #include "../../defs.h"
import "C"

import (
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/global"
	"github.com/neuvector/neuvector/share/osutil"
	"github.com/neuvector/neuvector/share/utils"
	log "github.com/sirupsen/logrus"
)

type ProcProfileBrief struct {  //存储进程概要信息
	name string  //进程名
	path string   //路径
}

type procGrpRef struct {  //用于维护系统进程的引用或列表，并且可以描述相互关联的进程组、服务和父子进程之间的关系等。
	name    string  //进程组名称
	path    string  //进程路径
	service string  //与进程相关的服务名称
	id      string  //进程标识符
	ppid    int   //进程的父进程标识符
}

// allowed parent scripts
var permitProcessGrp map[int]*procGrpRef = make(map[int]*procGrpRef)  //可以被用来存储进程组相关的信息，并支持按进程id查找
var k8sGrpProbe utils.Set = utils.NewSet()  //用户存储k8s集权探测器的配置信息

//更新监控引擎中的进程策略，并根据需要启动相关的探测器
//name  指定要更新的进程名称
//profile 包含新的进程策略信息
func (e *Engine) UpdateProcessPolicy(name string, profile *share.CLUSProcessProfile) (bool, *share.CLUSProcessProfile) {
	e.Mutex.Lock()  //互斥锁
	defer e.Mutex.Unlock()

	exist, ok := e.ProcessPolicy[name]
	if !ok || !reflect.DeepEqual(exist, profile) {  //如果进程策略不存在或新的策略内容与旧的策略内容不一致
		e.ProcessPolicy[name] = profile  //设置为新的进程策略
		for _, p := range profile.Process {
			if len(p.ProbeCmds) > 0 {  //检查是否配置了k8s检测器
				k8sGrpProbe.Add(name) // set the flag  //
				break
			}
		}
		return true, exist  //返回ture和旧的策略内容
	} else {
		return false, exist
	}
}

//监控引擎中的核心逻辑，用于根据进程名称和 ID 获取进程策略，并基于当前进程所处的组规则信息进行更新。
//name 指定要获取的进程名称
//id 指定当前进程的唯一标识符，通常是一个字符串
func (e *Engine) ObtainProcessPolicy(name, id string) (*share.CLUSProcessProfile, bool) {
	e.Mutex.Lock()  //互斥锁
	profile, _ := e.ProcessPolicy[name]  //根据名称获取进程策略
	e.Mutex.Unlock()
	if profile != nil { // the process policy per group has been fetched  //如果进程规则不为空
		if grp_profile, ok := e.getGroupRule(id); ok {
			if grp_profile == nil { // neuvector pods only //grp_profile为空 证明是neuvector pods
				return profile, true
			}
			grp_profile.Baseline = profile.Baseline // following original profile //将组规则中的基线版本设置为原始进程策略中的基线版本，并根据需要更新组规则中的执行模式（Mode）
			if grp_profile.Mode == "" {
				grp_profile.Mode = profile.Mode // update
			} else if grp_profile.Mode != profile.Mode { //如果两者不相等，则记录日志并忽略新的模式设置，仍然使用旧的组规则中的模式。
				// Detected: incomplete profile calculation, conflicts by timing
				// The new profile has not been calculated (it could be 5 seconds later) yet.
				// Just following the old group profile. it will be updated eventually.
				log.WithFields(log.Fields{"name": name, "latest-mode": profile.Mode, "group-mode": grp_profile.Mode}).Debug("GRP: ")
			}
			return grp_profile, true  //返回最终的进程策略和 true 作为结果
		}
	}

	// log.WithFields(log.Fields{"name": name}).Debug("GRP: process profile not ready")
	return nil, false
}

//用于判断给定的进程组名称是否需要在 Kubernetes 环境下执行探测器操作。
func (e *Engine) IsK8sGroupWithProbe(name string) bool {
	e.Mutex.Lock()
	defer e.Mutex.Unlock()
	return k8sGrpProbe.Contains(name)  //检查名为 name 的进程是否包含 Kubernetes 集群探测器。如果包含，则返回 true；否则返回 false。
}

//用于删除给定进程名称对应的进程策略，并将相关的 Kubernetes 进程组信息一并删除
func (e *Engine) DeleteProcessPolicy(name string) {
	e.Mutex.Lock()
	delete(e.ProcessPolicy, name) //从名为 name 的进程策略映射表中删除对应的条目。
	k8sGrpProbe.Remove(name)  //从 Kubernetes 进程组列表中删除名为 name 的进程组名称。
	log.WithFields(log.Fields{"name": name}).Debug("PROC: ")
	e.Mutex.Unlock()
}

//根据模式不同，返回相应的动作（默认）   ##5月21日19:38
//mode  字符串类型，表示防护模式
func defaultProcessAction(mode string) string {
	switch mode {
	case share.PolicyModeLearn:  //学习模式
		return share.PolicyActionLearn  //返回学习动作
	case share.PolicyModeEvaluate:  //监控模式
		return share.PolicyActionViolate  //返回违反策略
	case share.PolicyModeEnforce:  //保护模式
		return share.PolicyActionDeny  //返回阻止策略
	}
	return share.PolicyActionViolate   //默认返回违反策略
}

//用于比较两个结构体中特定字段的值，以确定他们是否匹配；
//entry
//proc
/*
type CLUSProcessProfileEntry struct {
	Name            string    `json:"name"`  //进程名称
	Path            string    `json:"path"`  //进程可执行文件的路径
	User            string    `json:"user"`  //启动进程的用户
	Uid             int32     `json:"uid"`  //启动进程的用户id
	Hash            []byte    `json:"hash"`  //进程可执行文件的hash值
	Action          string    `json:"action"`   //对这个进程执行的操作（阻止，允许）
	CfgType         TCfgType  `json:"cfg_type"`  //配置类型（如黑、白名单）
	CreatedAt       time.Time `json:"created_at"`  //创建时间
	UpdatedAt       time.Time `json:"updated_at"`  //最后更新时间
	Uuid            string    `json:"uuid"`   //用于唯一标识这个进程配置的uuid
	DerivedGroup    string    `json:"dgroup"`  //派生组名称（例如可以给予进程路径自动生成的组）
	AllowFileUpdate bool      `json:"allow_update"`  //是否允许更新进程可执行文件
	ProbeCmds       []string  `json:"probe_cmds"`  //用于探测进程可执行文件的shell命令列表
}
*/

/*用于进程策略的查找和匹配*/
func MatchProfileProcess(entry *share.CLUSProcessProfileEntry, proc *share.CLUSProcessProfileEntry) bool {
	// matching the major criteria: executable path  //匹配可执行文件的路径
	// all accepted:
	if entry.Name == "*" && (entry.Path == "*" || entry.Path == "/*") {
		return true
	}

	// application matching  //匹配应用程序
	i := strings.LastIndex(proc.Path, "/")  //分离出目录和文件名（返回最后一个/的位置）
	if i < 0 {  //如果最后一个/的位置为0，表示路径有问题
		log.WithFields(log.Fields{"exepath": proc.Path}).Debug("PROC: invalid path")
		return false
	}

	//
	dir := proc.Path[0:i]  //将目录赋予dir
	bin := proc.Path[i+1:]  //将可执行文件赋予bin
	// log.WithFields(log.Fields{"name": entry.Name, "path": entry.Path, "exepath": proc.Path, "exebin": bin, "exedir": dir}).Debug("PROC: ")
	if bin == entry.Name {
		if entry.Path == "*" || entry.Path == "" || entry.Path == "/*" {
			return true // match all
		} else if strings.HasSuffix(entry.Path, "/*") && entry.Name != "*" { // recursive match
			path := entry.Path[:len(entry.Path)-2]
			//	log.WithFields(log.Fields{"path": path, "dir": dir}).Debug("PROC: ")
			return strings.HasPrefix(dir, path)
		}
	}

	// wildcard name
	if entry.Name == "*" {
		if strings.HasSuffix(entry.Path, "/*") {
			path := entry.Path[:len(entry.Path)-2]
			//	log.WithFields(log.Fields{"path": path, "dir": dir}).Debug("PROC: ")
			return strings.HasPrefix(dir, path)
		} else if len(entry.ProbeCmds) > 0 { // probe shell commands
			return bin == entry.Path
		} else { // on a spefific file
			return proc.Path == entry.Path
		}
	} else { // recursive directory ( *, /bin/*, and /usr/*/nginx)
		if strings.HasSuffix(entry.Path, "/*") {
			path := entry.Path[:len(entry.Path)-2]
			return strings.HasPrefix(dir, path) && (entry.Name == proc.Name)
		} else if index := strings.Index(entry.Path, "/*/"); index > -1 {
			return strings.HasPrefix(dir, entry.Path[:index]) && (entry.Name == proc.Name) && (bin == filepath.Base(entry.Path))
		}
	}

	// regular cases
	if entry.Path != "" && entry.Path != "*" && entry.Path != "/*" {
		if proc.Path != entry.Path {
			return false
		}
	}

	// cases for busybox and others
	if proc.Name != entry.Name {
		return false
	}

	// log.WithFields(log.Fields{"name": entry.Name, "path": entry.Path, "execPath": proc.Path, "execnName": proc.Name}).Debug("PROC: matched")
	return true
}

//实现了一个进程策略的查找和匹配逻辑，并返回匹配的结果
func (e *Engine) ProcessPolicyLookup(name, id string, proc *share.CLUSProcessProfileEntry, pid int) (string, string, string, error) {
	group := name // service group
	profile, ok := e.ObtainProcessPolicy(name, id)
	if ok {
		var matchedEntry *share.CLUSProcessProfileEntry
		for _, p := range profile.Process {
			if profile.Mode == share.PolicyModeLearn && len(p.ProbeCmds) > 0 {
				//	if p.Name == "sh" && p.Path == "*" {		// replace
				//		if ok, app, _ := global.SYS.DefaultShellCmd(pid, "sh"); ok {
				//			p.Name = "*"
				//			p.Path = app
				//		}
				//	}
				continue // trigger a learning event
			}

			if MatchProfileProcess(p, proc) {
				matchedEntry = p
				proc.Action = p.Action
				proc.AllowFileUpdate = p.AllowFileUpdate
				proc.ProbeCmds = p.ProbeCmds
				break
			}
		}

		if matchedEntry != nil {
			proc.Uuid = matchedEntry.Uuid
			if matchedEntry.DerivedGroup != "" { // "" : internal reference for service group
				group = matchedEntry.DerivedGroup
			}
			if proc.Action == share.PolicyActionAllow {
				if profile.HashEnable {
					hash, _ := global.SYS.GetFileHash(pid, proc.Path)
					if hash != nil {
						if len(matchedEntry.Hash) == 0 {
							log.WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: update hash")
							matchedEntry.Hash = hash
							proc.Action = share.PolicyActionLearn
						} else if string(matchedEntry.Hash) != string(hash) {
							log.WithFields(log.Fields{"group": name, "path": proc.Path, "rec": matchedEntry.Hash, "hash": hash}).Debug("PROC: mismatched hash")
							proc.Action = share.PolicyActionViolate
						}
					} else {
						log.WithFields(log.Fields{"group": name, "path": proc.Path}).Debug("PROC: hash failed")
					}
				}

				// discovery mode and from a group rule
				// after re-calculated at group_profile, the service rules(updated at last) will become its derived_group ""
				// log.WithFields(log.Fields{"mode": profile.Mode, "name": name, "proc": proc, "group": group}).Debug("PROC: ")
				if profile.Mode == share.PolicyModeLearn && group != name {
					e.Mutex.Lock()
					prf, _ := e.ProcessPolicy[name]
					e.Mutex.Unlock()
					found := false
					for _, p := range prf.Process {
						if MatchProfileProcess(p, proc) {
							found = true
							break
						}
					}

					if !found {
						//	log.WithFields(log.Fields{"name": name, "proc": proc}).Debug("PROC: learnt")
						proc.Action = share.PolicyActionLearn
					}
				}
			} else { // deny decision
				// update deny decision in two other modes
				if profile.Mode != share.PolicyModeEnforce {
					proc.Action = share.PolicyActionViolate
				}
			}
		} else {
			if profile.Baseline == share.ProfileBasic  || !e.IsK8sGroupWithProbe(name){
				//not found in profile
				act := defaultProcessAction(profile.Mode)
				proc.Action = act
				proc.Uuid = share.CLUSReservedUuidNotAlllowed
			}
		}
		//log.WithFields(log.Fields{"group": name, "proc": proc}).Debug("")
	} else {
		//log.WithFields(log.Fields{"group": name, "proc": proc}).Debug("Profile not found")
		return "", "", "", errors.New("Profile not found")
	}
	return profile.Mode, profile.Baseline, group, nil
}

// matching the process name: suspicious process is defined by name only
//用于判断给定的进程名称是否被允许
//service 表示服务名称
//id  表示进程id
//name 表示进程名称
func (e *Engine) IsAllowedSuspiciousApp(service, id, name string) bool {
	profile, ok := e.ObtainProcessPolicy(service, id)  //获取进程策略
	if ok {
		for _, entry := range profile.Process {  //遍历每一条策略
			// all accepted:
			if entry.Name == "*" && (entry.Path == "*" || entry.Path == "/*") {  //相当于保护机制，如果进程路径为*或/*则直接放过
				return true
			}

			if name == entry.Name {
				return true
			}
		}
	}
	return false
}

// allowed by parent process name
// The program logic is located at faccess_linux.go: isAllowedByParentApp()
//用于判断给定的父进程名称是否允许派生出指定的子进程。
//
func (e *Engine) IsAllowedByParentApp(service, id, name, pname, ppath string, pgid int) bool {
	var allowed bool

	profile, ok := e.ObtainProcessPolicy(service, id)
	if ok {
		if procGrp, ok := permitProcessGrp[pgid]; ok {
			ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
			// log.WithFields(log.Fields{"pgid": pgid, "ppid": ppid, "procGrp": procGrp}).Debug("exist")
			if procGrp.id != id || ppid != procGrp.ppid {
				// invalid match, reset record
				delete(permitProcessGrp, pgid)
				procGrp = nil
			} else {
				return true
			}
		}

		for _, entry := range profile.Process {
			if entry.Action == share.PolicyActionAllow && strings.HasSuffix(entry.Name, "/*") {
				n := strings.TrimSuffix(entry.Name, "/*")
				if pname == n || name == n { // allowed parent name (including itself)
					if entry.Path == "" || entry.Path == "*" || entry.Path == "/*" {
						allowed = true
					}

					if !allowed && strings.HasSuffix(entry.Path, "/*") {
						p := strings.TrimSuffix(entry.Path, "/*")
						allowed = strings.HasPrefix(ppath, p)
					}

					if !allowed {
						allowed = entry.Path == ppath
					}
				}

				if allowed {
					ppid, _, _, _, _ := osutil.GetProcessPIDs(pgid)
					tagRef := &procGrpRef{name: n, path: entry.Path, service: service, id: id, ppid: ppid}
					permitProcessGrp[pgid] = tagRef
					log.WithFields(log.Fields{"pgid": pgid, "ppath": ppath, "tagRef": tagRef}).Debug()
					break
				}
			}
		}
	}
	return allowed
}

/////////////////////////////////////////////////////////////////////
func buildCustomizedProfile(serviceGroup, mode string, whtLst, blackLst []ProcProfileBrief) *share.CLUSProcessProfile {
	profile := &share.CLUSProcessProfile{
		Group:        serviceGroup,
		AlertDisable: false,
		HashEnable:   false,
		Mode:         mode,
	}

	// white list
	for _, ppw := range whtLst {
		wht := &share.CLUSProcessProfileEntry{
			Name:      ppw.name,
			Path:      ppw.path,
			Action:    share.PolicyActionAllow, // white list
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		profile.Process = append(profile.Process, wht)
	}

	// black list
	for _, ppb := range blackLst {
		blk := &share.CLUSProcessProfileEntry{
			Name:      ppb.name,
			Path:      ppb.path,
			Action:    share.PolicyActionDeny, // black list
			CreatedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
		}
		profile.Process = append(profile.Process, blk)
	}
	return profile
}

/////////////////////////////////////////////////////////////////////
func buildAllowAllProfile(serviceGroup string) *share.CLUSProcessProfile {
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		{"*", "*"},
	}
	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildNotAllowedProfile(serviceGroup string) *share.CLUSProcessProfile {
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		{"abcdefg", "ab556677"}, // unexpected item
	}
	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildManagerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: manager")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// python
		{"support", "/usr/bin/*"}, // support
		{"cli", "/usr/bin/*"},     // cli

		// manager cores :  wildcard
		{"*", "/usr/lib/jvm/*"}, // JVM
		//	{"java", "/usr/lib/jvm/java-1.8-openjdk/jre/bin/java"}

		// busybox
		{"busybox", "/bin/busybox"}, // below busybox and its symbolic links
		{"lsof", "/bin/busybox"},    // replaced
		{"netstat", "/bin/busybox"},
		{"ps", "/bin/busybox"}, // replaced
		{"sh", "/bin/busybox"},
		{"touch", "/bin/busybox"}, // detect container layer on the AUFS
		{"uname", "/bin/busybox"}, // cli
		{"which", "/bin/busybox"}, // cli
		{"cat", "*"},              // k8s readiness and openshift operations
		{"echo", "/bin/busybox"},

		// below entries for debug purpose : docker exec -ti manager sh
		{"sh", "/bin/dash"},
		{"ip", "/sbin/ip"},
		{"ps", "/usr/bin/ps"},   // new procps package
		{"top", "/usr/bin/top"}, // new procps package
		{"kill", "/bin/kill"},   // new procps package
		{"ls", "/bin/busybox"},
		{"kill", "/bin/busybox"}, // replaced
		{"top", "/bin/busybox"},  // replaced
		{"nslookup", "/bin/busybox"},
		{"nc", "/bin/busybox"},
		{"tee", "/usr/bin/tee"},
		{"stat", "/usr/bin/stat"}, // bench scripts
		{"stty", "/bin/busybox"},  // python3.9

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
		{"grep", "*"},           // CIS bench tests
		{"pgrep", "*"},
		{"sed", "*"},
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildScannerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: scanner")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// scanner cores :  wildcard
		{"monitor", "/usr/local/bin/monitor"},
		{"scanner", "/usr/local/bin/scanner"},
		{"scannerTask", "/usr/local/bin/scannerTask"},

		// busybox
		{"busybox", "/bin/busybox"}, // below busybox and its symbolic links
		{"netstat", "/bin/busybox"},
		{"sh", "/bin/busybox"},
		{"uname", "/bin/busybox"},
		{"which", "/bin/busybox"},
		{"touch", "/bin/busybox"}, // detect container layer on the AUFS
		{"cat", "*"},              // k8s readiness and openshift operations

		// below entries for debug purpose : docker exec -ti manager sh
		{"sh", "/bin/dash"},
		{"ip", "/sbin/ip"},
		{"ps", "/usr/bin/ps"}, // new procps package
		{"kill", "/bin/kill"}, // new procps package
		{"ls", "/bin/busybox"},
		{"lsof", "/usr/bin/lsof"}, // new lsof package
		{"nslookup", "/bin/busybox"},
		{"nc", "/bin/busybox"},
		{"echo", "/bin/busybox"},
		{"tee", "/usr/bin/tee"},
		{"stat", "/usr/bin/stat"}, // bench scripts

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
		{"grep", "*"},           // CIS bench tests
		{"pgrep", "*"},
		{"sed", "*"},
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildControllerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: controller")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// /usr/local/bin
		{"consul", "*"}, // monitor also calls it through a shell command
		{"controller", "/usr/local/bin/controller"},
		{"monitor", "/usr/local/bin/monitor"},
		{"nstools", "/usr/local/bin/nstools"},
		{"tcpdump", "/usr/local/bin/tcpdump"},
		{"opa", "/usr/local/bin/opa"},

		// tools
		{"ethtool", "/usr/sbin/ethtool"}, // network hardware setting
		{"sysctl", "/sbin/sysctl"},       // monitor tool
		{"tc", "/sbin/tc"},               // traffic control
		{"getconf", "/usr/bin/getconf"},  // get configuration values
		{"getent", "/usr/bin/getent"},    // get entries from Name Service Switch libraries
		{"iconv", "/usr/bin/iconv"},      // convert encoding of given files from one encoding to another
		{"lsof", "/usr/bin/lsof"},        // new lsof package

		// busybox
		{"busybox", "/bin/busybox"}, // below busybox and its symbolic links
		{"mv", "/bin/busybox"},
		{"lsof", "/bin/busybox"}, // replaced
		{"netstat", "/bin/busybox"},
		{"ps", "/bin/busybox"},
		{"sh", "/bin/busybox"},
		{"touch", "/bin/busybox"},       // detect container layer on the AUFS
		{"cat", "*"},                    // k8s readiness and openshift operations
		{"teardown.sh", "/bin/busybox"}, // monitor tool

		// below entries for debug purpose : docker exec -ti allinone sh
		{"sh", "/bin/dash"},
		{"ip", "/sbin/ip"},
		{"ps", "/usr/bin/ps"},   // new procps package
		{"top", "/usr/bin/top"}, // new procps package
		{"kill", "/bin/kill"},   // new procps package
		{"ls", "/bin/busybox"},
		{"kill", "/bin/busybox"}, // replaced
		{"top", "/bin/busybox"},  // replaced
		{"nslookup", "/bin/busybox"},
		{"nc", "/bin/busybox"},
		{"echo", "/bin/busybox"},
		{"tee", "/usr/bin/tee"},
		{"stat", "/usr/bin/stat"}, // bench scripts

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
		{"grep", "*"},           // CIS bench tests
		{"pgrep", "*"},
		{"sed", "*"},
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildEnforcerProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: enforcer")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// /usr/local/bin
		{"agent", "/usr/local/bin/agent"},
		{"consul", "*"}, // monitor also calls it through a shell command
		{"dp", "/usr/local/bin/dp"},
		{"monitor", "/usr/local/bin/monitor"},
		{"nstools", "/usr/local/bin/nstools"},
		{"tcpdump", "/usr/local/bin/tcpdump"},
		{"pathWalker", "/usr/local/bin/pathWalker"},

		// tools
		{"ethtool", "/usr/sbin/ethtool"}, // network hardware setting
		{"tc", "/sbin/tc"},               // traffic control
		{"modinfo", "/sbin/modinfo"},     // monitor tool: configure.sh
		{"getconf", "/usr/bin/getconf"},  // get configuration values
		{"getent", "/usr/bin/getent"},    // get entries from Name Service Switch libraries
		{"iconv", "/usr/bin/iconv"},      // convert encoding of given files from one encoding to another
		{"lsof", "/usr/bin/lsof"},        // new lsof package
		{"curl", "/usr/bin/curl"},        // cis benchmark
		{"jq", "/usr/bin/jq"},            // cis benchmark
		{"timeout", "/usr/bin/timeout"},  // could be used by tcpdump

		// busybox
		{"busybox", "/bin/busybox"}, // below busybox and its symbolic links
		{"mv", "/bin/busybox"},
		{"lsof", "/bin/busybox"}, // replaced
		{"netstat", "/bin/busybox"},
		{"ps", "/bin/busybox"},
		{"sh", "/bin/busybox"},
		{"touch", "/bin/busybox"},        // detect container layer on the AUFS
		{"cat", "*"},                     // k8s readiness and openshift operations
		{"configure.sh", "/bin/busybox"}, // monitor tool
		{"teardown.sh", "/bin/busybox"},  // monitor tool

		// below entries for debug purpose : docker exec -ti allinone sh
		{"sh", "/bin/dash"},
		{"ip", "/sbin/ip"},
		{"iptables", "/sbin/xtables-legacy-multi"},      // dp
		{"iptables-save", "/sbin/xtables-legacy-multi"}, // dp
		{"ps", "/usr/bin/ps"},                           // new procps package
		{"top", "/usr/bin/top"},                         // new procps package
		{"kill", "/bin/kill"},                           // new procps package
		{"ls", "/bin/busybox"},
		{"kill", "/bin/busybox"}, // replaced
		{"top", "/bin/busybox"},  // replaced
		{"nslookup", "/bin/busybox"},
		{"nc", "/bin/busybox"},
		{"echo", "/bin/busybox"},
		{"tee", "/usr/bin/tee"},
		{"stat", "/usr/bin/stat"}, // bench scripts

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
		{"grep", "*"},           // CIS bench tests
		{"pgrep", "*"},
		{"sed", "*"},
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

/////////////////////////////////////////////////////////////////////
func buildAllinOneProfileList(serviceGroup string) *share.CLUSProcessProfile {
	log.WithFields(log.Fields{"serviceGroup": serviceGroup}).Debug("PROC: allInOne")
	var whtLst []ProcProfileBrief = []ProcProfileBrief{
		/////////////////////////////////
		// python: python2.7 or python3.8
		{"python", "/usr/bin/*"},      // runtime-gdb.py
		{"supervisord", "/usr/bin/*"}, // start-up
		{"support", "/usr/bin/*"},     // support
		{"cli", "/usr/bin/*"},         // cli

		// manager cores :  wildcard
		{"*", "/usr/lib/jvm/*"}, // JVM
		// {"java", "/usr/lib/jvm/java-1.8-openjdk/jre/bin/java"}

		// /usr/local/bin
		//  {"*", "/usr/local/bin/*"}, // wildcard for below commented execs
		{"agent", "/usr/local/bin/agent"},
		{"consul", "*"}, // monitor also calls it through a shell command
		{"controller", "/usr/local/bin/controller"},
		{"dp", "/usr/local/bin/dp"},
		{"monitor", "/usr/local/bin/monitor"},
		{"nstools", "/usr/local/bin/nstools"},
		{"tcpdump", "/usr/local/bin/tcpdump"},
		{"opa", "/usr/local/bin/opa"},
		{"pathWalker", "/usr/local/bin/pathWalker"},

		// tools
		{"ethtool", "/usr/sbin/ethtool"}, // network hardware setting
		{"tc", "/sbin/tc"},               // traffic control
		{"modinfo", "/sbin/modinfo"},     // monitor tool: configure.sh
		{"getconf", "/usr/bin/getconf"},  // get configuration values
		{"getent", "/usr/bin/getent"},    // get entries from Name Service Switch libraries
		{"iconv", "/usr/bin/iconv"},      // convert encoding of given files from one encoding to another
		{"lsof", "/usr/bin/lsof"},        // new lsof package
		{"curl", "/usr/bin/curl"},        // cis benchmark
		{"jq", "/usr/bin/jq"},            // cis benchmark
		{"timeout", "/usr/bin/timeout"},  // could be used by tcpdump

		// busybox
		{"busybox", "/bin/busybox"}, // below busybox and its symbolic links
		{"mv", "/bin/busybox"},
		{"lsof", "/bin/busybox"}, // replaced
		{"netstat", "/bin/busybox"},
		{"ps", "/bin/busybox"},
		{"sh", "/bin/busybox"},
		{"touch", "/bin/busybox"},        // detect container layer on the AUFS
		{"uname", "/bin/busybox"},        // cli
		{"which", "/bin/busybox"},        // cli
		{"cat", "*"},                     // k8s readiness and openshift operations
		{"configure.sh", "/bin/busybox"}, // monitor tool
		{"teardown.sh", "/bin/busybox"},  // monitor tool
		{"stty", "/bin/busybox"},         // python3.9

		// below entries for debug purpose : docker exec -ti allinone sh
		{"sh", "/bin/dash"},
		{"ip", "/sbin/ip"},
		{"iptables", "/sbin/xtables-legacy-multi"},      // dp
		{"iptables-save", "/sbin/xtables-legacy-multi"}, // dp
		{"ps", "/usr/bin/ps"},                           // new procps package
		{"top", "/usr/bin/top"},                         // new procps package
		{"kill", "/bin/kill"},                           // new procps package
		{"ls", "/bin/busybox"},
		{"kill", "/bin/busybox"}, // replaced
		{"top", "/bin/busybox"},  // replaced
		{"nslookup", "/bin/busybox"},
		{"nc", "/bin/busybox"},
		{"echo", "/bin/busybox"},
		{"tee", "/usr/bin/tee"},

		// k8s or openshift environment
		{"pause", "/pause"},     // k8s, pause
		{"pod", "/usr/bin/pod"}, // openshift, pod
		{"mount", "*"},          // k8s volume plug-in
		{"grep", "*"},           // CIS bench tests
		{"pgrep", "*"},
		{"sed", "*"},
	}

	return buildCustomizedProfile(serviceGroup, share.PolicyModeEnforce, whtLst, nil)
}

///
func (e *Engine) InsertNeuvectorProcessProfilePolicy(group, role string) {
	log.WithFields(log.Fields{"group": group, "role": role}).Debug("PROC:")
	var profile *share.CLUSProcessProfile
	switch role {
	case "enforcer":
		profile = buildEnforcerProfileList(group)
	case "controller":
		profile = buildControllerProfileList(group)
	case "manager":
		profile = buildManagerProfileList(group)
	case "controller+enforcer+manager", "controller+enforcer", "allinone":
		profile = buildAllinOneProfileList(group)
	case "scanner":
		profile = buildScannerProfileList(group)
	case "updater", "fetcher": // should not have protection, phase-out soon
		profile = buildAllowAllProfile(group)
	}

	// now, we use minimum policy for other neuvector containers
	if profile == nil {
		profile = buildAllinOneProfileList(group)
		// profile = buildNotAllowedProfile(group)		// TODO: enforce it to prevent hackers
	}

	e.UpdateProcessPolicy(group, profile)
}
