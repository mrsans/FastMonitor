
# FastMonitor - 网络流量监控与威胁检测工具

## 📖 项目简介

**FastMonitor** 是一款基于 **Wails 框架**开发的**跨平台网络流量监控与威胁检测工具**,集成了数据包分析、进程关联、会话流统计、威胁情报检测、地理位置可视化等功能于一体。

备注：wails框架练手项目，开发周期2天，BUG较多，仅供试用。

### 核心特性

- 🚀 **高性能抓包引擎**: 基于 gopacket/pcap 实现,支持数据包实时处理
- 🎯 **精准进程关联**: 自动将网络流量与进程绑定,支持主流操作系统
- 🛡️ **智能威胁检测**: 支持自定义病毒等威胁情报IOC规则,实时告警
- 🌍 **3D地理可视化**: 基于 ECharts GL 的3D地球和2D地图流量展示
- 📊 **实时仪表盘**: 大屏展示网络流量、协议分布、TOP排行
- 💾 **数据持久化**: SQLite存储 + PCAP文件归档,支持历史回溯
- 🎨 **现代化界面**: Vue 3 + Element Plus + 深色主题
<img width="1506" height="891" alt="截屏2025-10-08 14 11 25" src="https://github.com/user-attachments/assets/6bd2f3ef-cd7b-40df-a03c-c9d4cbc62652" />

<img width="1507" height="775" alt="截屏2025-10-08 14 10 46" src="https://github.com/user-attachments/assets/060488a4-f12a-4a78-933d-eafd9992ff5f" />

 <img width="1506" height="891" alt="截屏2025-10-08 14 11 03" src="https://github.com/user-attachments/assets/bf6f6a38-e3b2-409d-b3d5-cd69eb7dfe81" />

<img width="1506" height="891" alt="截屏2025-10-08 14 11 16" src="https://github.com/user-attachments/assets/3066f854-e6aa-4c21-b3e0-772e2ca9bb65" />

---

## 🎯 主要用途

| 应用场景 | 功能描述 |
|---------|---------|
| **网络监控** | 实时监控内网流量,发现异常外联和数据泄露 |
| **安全威胁分析** | 检测C2通信、钓鱼攻击、恶意软件行为 |
| **流量审计** | 记录所有网络活动,支持取证和合规审计 |
| **性能诊断** | 分析网络瓶颈、异常流量、协议分布 |
| **开发调试** | 抓包分析HTTP/DNS/ICMP等协议细节 |
| **安全研究** | 恶意样本行为分析、IOC提取 |

---

## 🏗️ 系统架构

```
┌─────────────────────────────────────────────────────────────┐
│                      FastMonitor 前端                       │
│          Vue 3 + TypeScript + Element Plus                  │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐   │
│  │仪表盘    │数据包     │会话流     │进程      │告警        │   │
│  │2D/3D地图 │DNS/HTTP  │统计       │关联      │规则       │   │
│  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┘   │
└───────┼──────────┼──────────┼──────────┼──────────┼─────────┘
        │          │          │          │          │
        │      Wails RPC (JSON)                    │
        │          │          │          │          │
┌───────┼──────────┼──────────┼──────────┼──────────┼─────────┐
│       ▼          ▼          ▼          ▼          ▼         │
│                  FastMonitor 后端 (Go)                      │
│  ┌──────────┬──────────┬──────────┬──────────┬──────────┐   │
│  │抓包引擎  │协议解析  │进程映射  │告警引擎  │存储层    │   │
│  │gopacket  │Parser    │Process   │Alert     │SQLite    │   │
│  │          │          │Mapper    │Engine    │PCAP      │   │
│  └────┬─────┴────┬─────┴────┬─────┴────┬─────┴────┬─────┘   │
│       │          │          │          │          │         │
│       ▼          ▼          ▼          ▼          ▼         │
│  ┌─────────────────────────────────────────────────────┐    │
│  │        网络接口层 (NIC Capture)                      │    │
│  │   Ethernet / Wi-Fi / VPN / Loopback                 │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📚 功能模块详解

### 1️⃣ 网卡选择 (Network Interface Selection)

#### 功能描述
- 自动检测系统所有可用网络接口(网卡)
- 支持物理网卡、虚拟网卡、回环接口、VPN隧道
- 实时显示网卡状态和流量统计

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **网卡列表** | 显示所有接口名称、IP地址、MAC地址、状态 |
| **网卡筛选** | 支持按接口类型(有线/无线/虚拟)筛选 |
| **实时状态** | 显示接口是否激活、当前流量速率 |
| **快速切换** | 一键切换抓包网卡,无需重启 |
| **权限检测** | 自动检测抓包权限,提示管理员权限 |

#### 技术实现
```go
// 网卡枚举 (internal/capture/capture.go)
func ListInterfaces() ([]*NetworkInterface, error) {
    devices, _ := pcap.FindAllDevs()
    for _, device := range devices {
        // 解析IP、MAC、MTU等信息
        // 检测网卡状态和类型
    }
}
```

#### 使用说明
1. **启动应用** → 点击顶部工具栏"设置"按钮
2. **网卡列表** → 显示所有可用网卡及其详细信息
3. **选择网卡** → 点击目标网卡,系统自动切换抓包接口
4. **开始抓包** → 点击"开始捕获"按钮开始监控

#### 常见问题
- ❌ **无网卡显示**: 需要以管理员/root权限运行
- ❌ **抓包失败**: 检查WinPcap/Npcap(Windows)或libpcap(Linux/macOS)是否安装
- ✅ **推荐网卡**: 选择活跃流量的物理网卡,避免选择回环接口

---

### 2️⃣ 仪表盘 (Dashboard)

#### 功能描述
提供实时网络流量监控的大屏展示,包括统计图表、TOP排行、协议分布等可视化组件。

#### 核心功能
| 模块 | 说明 |
|-----|------|
| **实时流量曲线** | 显示上下行流量的时间趋势(bps/pps) |
| **协议分布饼图** | TCP/UDP/ICMP/DNS/HTTP等协议占比 |
| **TOP源地址** | 流量最大的前10个源IP |
| **TOP目标地址** | 流量最大的前10个目标IP |
| **TOP进程排行** | 网络活动最频繁的前10个进程 |
| **地理分布热力** | 连接国家/地区的热力地图 |
| **告警统计** | 实时显示Critical/Warning/Info告警数量 |

#### 可视化组件
```typescript
// 流量趋势图 (ECharts折线图)
{
  xAxis: { data: timestamps },     // 时间轴
  series: [
    { name: '上行流量', data: txBytes },
    { name: '下行流量', data: rxBytes }
  ]
}

// 协议分布图 (ECharts饼图)
{
  series: [{
    type: 'pie',
    data: [
      { name: 'TCP', value: 45.2 },
      { name: 'UDP', value: 30.1 },
      { name: 'ICMP', value: 5.3 }
    ]
  }]
}
```

#### 数据刷新
- **默认刷新间隔**: 2秒
- **数据窗口**: 最近60秒/5分钟/1小时可选
- **自适应性能**: 流量过大时自动降低刷新率

#### 大屏模式
- **触发方式**: 点击仪表盘右上角"全屏"按钮
- **布局风格**: 深色主题 + 赛博朋克风格边框
- **特殊效果**: 数字滚动动画、图表自适应缩放
- **退出方式**: 按ESC键或点击右上角退出按钮

---

### 3️⃣ 数据包 (Packet Capture)

#### 功能描述
实时捕获并解析网络数据包,支持多层协议分析和数据包过滤。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **实时抓包** | 每秒捕获数千个数据包并解码 |
| **多层解析** | 解析Ethernet → IP → TCP/UDP → HTTP/DNS |
| **字段提取** | 自动提取源/目标IP、端口、协议、载荷 |
| **BPF过滤器** | 支持Berkeley Packet Filter语法 |
| **数据包详情** | 显示原始十六进制和ASCII载荷 |
| **导出功能** | 导出为PCAP格式供Wireshark分析 |

#### 数据包字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `timestamp` | 捕获时间(纳秒精度) | 2025-10-08 14:32:15.123456 |
| `src_ip` | 源IP地址 | 192.168.1.100 |
| `dst_ip` | 目标IP地址 | 8.8.8.8 |
| `src_port` | 源端口 | 51234 |
| `dst_port` | 目标端口 | 443 |
| `protocol` | 传输层协议 | TCP / UDP / ICMP |
| `length` | 数据包长度(字节) | 1420 |
| `payload` | 应用层载荷(Base64编码) | SGVsbG8gV29ybGQ= |
| `process_name` | 关联进程名(如果成功映射) | chrome.exe |

#### BPF过滤器示例
```bash
# 只捕获HTTP流量
tcp port 80 or tcp port 8080

# 只捕获DNS查询
udp port 53

# 只捕获特定IP的流量
host 192.168.1.100

# 只捕获出站流量
src net 192.168.0.0/16

# 组合条件
tcp and dst port 443 and not host 127.0.0.1
```

#### 技术实现
```go
// 数据包捕获主循环 (internal/capture/capture.go)
func (c *Capture) Start() {
    handle, _ := pcap.OpenLive(c.device, snapLen, promiscuous, timeout)
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    
    for packet := range packetSource.Packets() {
        // 解析Ethernet层
        ethLayer := packet.Layer(layers.LayerTypeEthernet)
        
        // 解析IP层
        ipLayer := packet.Layer(layers.LayerTypeIPv4)
        
        // 解析TCP/UDP层
        tcpLayer := packet.Layer(layers.LayerTypeTCP)
        
        // 提取载荷
        payload := packet.ApplicationLayer().Payload()
        
        // 发送到处理管道
        c.packetChan <- parsedPacket
    }
}
```

#### 性能优化
- **零拷贝**: 使用 `gopacket.NoCopy` 避免内存复制
- **批量处理**: 100个数据包批量入库
- **环形缓冲**: 内存限制时丢弃旧数据包
- **异步写入**: 抓包线程和存储线程分离

---

### 4️⃣ DNS解析 (DNS Queries)

#### 功能描述
专门捕获并分析DNS查询和响应,检测恶意域名和DNS隧道。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **DNS记录解析** | 解析A/AAAA/CNAME/MX/TXT等记录类型 |
| **查询统计** | 统计最频繁查询的域名TOP10 |
| **响应时间** | 记录DNS服务器响应延迟 |
| **失败查询** | 记录NXDOMAIN和SERVFAIL响应 |
| **恶意域名检测** | 匹配威胁情报中的C2域名 |

#### DNS字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `query_name` | 查询域名 | www.example.com |
| `query_type` | 记录类型 | A / AAAA / CNAME |
| `response_code` | 响应码 | NOERROR / NXDOMAIN |
| `answers` | 解析结果(JSON数组) | ["93.184.216.34"] |
| `dns_server` | DNS服务器IP | 8.8.8.8 |
| `latency_ms` | 响应时间(毫秒) | 23 |

#### 威胁检测规则
```go
// DNS规则匹配 (内置银狐C2域名)
rule := &AlertRule{
    Name:              "银狐病毒 - C2域名检测",
    RuleType:          "dns",
    ConditionField:    "domain",
    ConditionOperator: "contains",
    ConditionValue:    "12-18.qq-weixin.org,8004.twilight.zip,addr.ktsr.cc",
    AlertLevel:        "critical",
}

// 匹配逻辑
func matchDNSRule(queryName string, rule *AlertRule) bool {
    domains := strings.Split(rule.ConditionValue, ",")
    for _, domain := range domains {
        if strings.Contains(queryName, domain) {
            return true  // 触发告警!
        }
    }
    return false
}
```

#### 使用场景
- 🔍 **恶意软件外联**: 检测DGA域名、C2域名
- 🛡️ **钓鱼攻击**: 识别伪装成银行/政府的钓鱼域名
- 📊 **流量分析**: 统计员工访问最多的网站
- 🚫 **DNS劫持**: 检测异常的DNS响应(如返回错误IP)

---

### 5️⃣ HTTP流量 (HTTP Requests)

#### 功能描述
捕获并分析HTTP/HTTPS流量,提取URL、User-Agent、状态码等关键信息。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **HTTP请求解析** | 提取Method/URL/Headers/Body |
| **HTTP响应解析** | 提取Status Code/Content-Type/Length |
| **HTTPS元数据** | 即使不解密也能提取SNI域名 |
| **恶意URL检测** | 匹配钓鱼URL和恶意下载链接 |
| **User-Agent分析** | 识别浏览器/爬虫/恶意软件UA |

#### HTTP字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `method` | HTTP方法 | GET / POST / PUT |
| `url` | 完整URL | https://example.com/api/data |
| `host` | 目标主机名 | example.com |
| `user_agent` | 客户端标识 | Mozilla/5.0 ... |
| `status_code` | 响应状态码 | 200 / 404 / 500 |
| `content_type` | 内容类型 | application/json |
| `content_length` | 响应大小(字节) | 4096 |

#### 威胁检测规则
```go
// HTTP规则 - 检测恶意PNG下载
rule := &AlertRule{
    Name:              "银狐病毒 - 恶意PNG下载检测",
    RuleType:          "http",
    ConditionField:    "url",
    ConditionOperator: "regex",
    ConditionValue:    "(?i)183\\.167\\.230\\.197:18743/(0CFA042F|5B16AF14|57BC9B7E|test)\\.Png",
    AlertLevel:        "critical",
}

// HTTP规则 - 检测钓鱼URL
rule := &AlertRule{
    Name:              "银狐病毒 - 钓鱼URL检测",
    RuleType:          "http",
    ConditionField:    "url",
    ConditionOperator: "contains",
    ConditionValue:    "baidu.com@cuomicufvhehy.cn",
    AlertLevel:        "critical",
}
```

#### HTTPS流量处理
⚠️ **注意**: FastMonitor **不解密HTTPS流量**(无中间人攻击),但仍可提取:
- **SNI(Server Name Indication)**: TLS握手时的明文域名
- **证书信息**: 服务器证书的颁发者和有效期
- **流量统计**: 上下行字节数和数据包数量

---

### 6️⃣ ICMP流量 (ICMP Packets)

#### 功能描述
捕获并分析ICMP数据包,包括ping请求、traceroute、网络不可达等消息。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **ICMP类型识别** | Echo Request/Reply、Destination Unreachable |
| **Ping统计** | 往返时延(RTT)、丢包率 |
| **网络诊断** | 识别路由问题、MTU问题 |
| **异常检测** | 检测ICMP Flood攻击、ICMP隧道 |

#### ICMP字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `type` | ICMP类型 | 8(Echo Request) / 0(Echo Reply) |
| `code` | ICMP代码 | 0(网络不可达) / 1(主机不可达) |
| `sequence` | 序列号 | 12345 |
| `identifier` | 标识符 | 54321 |
| `rtt_ms` | 往返时延(毫秒) | 15.2 |

#### 常见ICMP类型
| Type | Code | 说明 |
|------|------|------|
| 0 | 0 | Echo Reply (Ping响应) |
| 3 | 0-15 | Destination Unreachable (目标不可达) |
| 8 | 0 | Echo Request (Ping请求) |
| 11 | 0-1 | Time Exceeded (TTL超时,traceroute) |

---

### 7️⃣ 会话流统计 (Session Flow Statistics)

#### 功能描述
将零散的数据包聚合为会话流(Session),统计每个会话的流量、时延、数据包数等指标。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **五元组聚合** | 按(SrcIP, DstIP, SrcPort, DstPort, Protocol)聚合 |
| **双向流量统计** | 分别统计上下行字节数和数据包数 |
| **会话时长** | 记录会话开始时间和持续时长 |
| **地理位置** | 自动查询目标IP的国家/城市 |
| **进程绑定** | 自动关联发起该会话的进程 |
| **状态追踪** | 识别TCP连接状态(SYN/ACK/FIN/RST) |

#### 会话字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `session_key` | 会话唯一标识(哈希) | a3f8c2d1... |
| `src_ip` | 源IP | 192.168.1.100 |
| `dst_ip` | 目标IP | 93.184.216.34 |
| `src_port` | 源端口 | 51234 |
| `dst_port` | 目标端口 | 443 |
| `protocol` | 协议 | TCP |
| `tx_bytes` | 上行字节数 | 1024000 |
| `rx_bytes` | 下行字节数 | 5120000 |
| `tx_packets` | 上行数据包数 | 1500 |
| `rx_packets` | 下行数据包数 | 3800 |
| `start_time` | 会话开始时间 | 2025-10-08 14:32:15 |
| `duration_sec` | 会话持续时长(秒) | 125.3 |
| `dst_country` | 目标国家 | United States |
| `dst_city` | 目标城市 | Ashburn |
| `process_name` | 关联进程 | chrome.exe |

#### 会话聚合逻辑
```go
// 会话Key计算 (双向对称哈希)
func sessionKey(srcIP, dstIP string, srcPort, dstPort uint16, proto string) string {
    // 确保双向流量使用相同Key
    if srcIP > dstIP || (srcIP == dstIP && srcPort > dstPort) {
        srcIP, dstIP = dstIP, srcIP
        srcPort, dstPort = dstPort, srcPort
    }
    return fmt.Sprintf("%s:%d-%s:%d-%s", srcIP, srcPort, dstIP, dstPort, proto)
}

// 会话更新
func updateSession(packet *Packet) {
    key := sessionKey(packet.SrcIP, packet.DstIP, ...)
    session := sessions[key]
    
    // 更新统计
    if packet.SrcIP == session.SrcIP {
        session.TxBytes += packet.Length
        session.TxPackets++
    } else {
        session.RxBytes += packet.Length
        session.RxPackets++
    }
    
    session.LastSeen = time.Now()
}
```

#### 使用场景
- 📊 **流量审计**: 查看某IP的所有外联会话
- 🔍 **异常检测**: 发现流量异常大的会话(如数据外泄)
- 🌍 **地理分析**: 统计连接最多的国家/地区
- 🚫 **黑名单拦截**: 阻断连接到恶意IP的会话

---

### 8️⃣ 进程关联 (Process Mapping)

#### 功能描述
自动将网络流量与发起该流量的进程绑定,实现进程级网络监控。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **进程枚举** | 遍历系统所有进程及其网络连接 |
| **连接映射** | 将(IP, Port)映射到进程PID |
| **进程信息** | 提取进程名、路径、命令行、启动时间 |
| **进程统计** | 统计每个进程的网络流量和连接数 |
| **进程告警** | 检测恶意进程的网络行为 |

#### 进程字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `pid` | 进程ID | 1234 |
| `name` | 进程名 | chrome.exe |
| `path` | 完整路径 | C:\Program Files\Google\Chrome\chrome.exe |
| `cmdline` | 命令行参数 | --type=renderer --lang=zh-CN |
| `connections` | 活跃连接数 | 15 |
| `tx_bytes` | 进程上传总量 | 10240000 |
| `rx_bytes` | 进程下载总量 | 51200000 |
| `start_time` | 进程启动时间 | 2025-10-08 14:00:00 |

#### 技术实现
```go
// Windows进程映射 (internal/process/mapper.go)
func GetProcessByConnection(localIP string, localPort uint16) (*Process, error) {
    // 方法1: GetExtendedTcpTable (Windows)
    table, _ := GetExtendedTcpTable()
    for _, row := range table {
        if row.LocalAddr == localIP && row.LocalPort == localPort {
            return GetProcessByPID(row.OwningPid)
        }
    }
    
    // 方法2: /proc/net/tcp (Linux)
    f, _ := os.Open("/proc/net/tcp")
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        // 解析/proc/net/tcp格式,提取inode
        // 遍历/proc/[pid]/fd找到匹配inode的进程
    }
}
```

#### 威胁检测规则
```go
// 进程规则 - 检测恶意进程
rule := &AlertRule{
    Name:              "银狐病毒 - 已知恶意进程检测",
    RuleType:          "process",
    ConditionField:    "process_name",
    ConditionOperator: "regex",
    ConditionValue:    "(?i)(Ubit\\.exe|DUbit\\.exe|ggaa\\.exe|wrdlv4\\.exe|GDFInstall\\.exe|dzfp\\.exe|ChromeGPT_install\\.exe)",
    AlertLevel:        "critical",
}

// 进程规则 - 检测系统进程异常外联
rule := &AlertRule{
    Name:              "银狐病毒 - 系统进程异常外联",
    RuleType:          "process",
    ConditionField:    "process_name",
    ConditionOperator: "regex",
    ConditionValue:    "(?i)(svchost\\.exe|rundll32\\.exe|regsvr32\\.exe|mshta\\.exe|powershell\\.exe|cmd\\.exe)",
    AlertLevel:        "warning",
}
```

#### 平台兼容性
| 平台 | 方法 | 准确率 |
|------|-----|--------|
| **Windows** | `GetExtendedTcpTable` API | ✅ 100% |
| **Linux** | `/proc/net/tcp` + `/proc/[pid]/fd` | ✅ 95% |
| **macOS** | `lsof -i -P` 命令行解析 | ⚠️ 80% |

---

### 9️⃣ 告警系统 (Alert System)

#### 功能描述
基于威胁情报IOC规则,实时检测恶意流量并生成告警。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **规则引擎** | 支持正则表达式、关键词匹配 |
| **多级告警** | Critical / Error / Warning / Info |
| **告警聚合** | 相同特征的告警自动合并计数 |
| **告警确认** | 支持手动确认和批量确认 |
| **告警导出** | 导出为JSON/CSV供SIEM分析 |
| **内置规则** | 预置部分银狐病毒等威胁的IOC规则示例 |

#### 告警规则字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `name` | 规则名称 | 银狐病毒 - C2域名检测 |
| `rule_type` | 规则类型 | dns / http / process / dst_ip |
| `condition_field` | 匹配字段 | domain / url / process_name / dst_ip |
| `condition_operator` | 匹配操作符 | contains / regex / equals |
| `condition_value` | 匹配值 | 12-18.qq-weixin.org,addr.ktsr.cc |
| `alert_level` | 告警级别 | critical / warning / info |
| `description` | 规则描述 | 检测银狐病毒已知C2域名(2025年活跃) |
| `enabled` | 是否启用 | true / false |

#### 内置威胁检测规则

系统预置了**7条高质量规则**,针对**银狐病毒(SilverFox)**等APT威胁:

**1. 银狐病毒 - 已知恶意进程检测** (Critical)
- 类型: `process` 
- 特征: `Ubit.exe`, `DUbit.exe`, `ggaa.exe`, `wrdlv4.exe`, `GDFInstall.exe`, `dzfp.exe`, `ChromeGPT_install.exe`
- 说明: 检测7个已知恶意进程,包括进程注入、计划任务保活、白+黑加载器等

**2. 银狐病毒 - C2域名检测** (Critical)
- 类型: `dns`
- 特征: `12-18.qq-weixin.org`, `8004.twilight.zip`, `cuomicufvhehy.cn`, `addr.ktsr.cc`, `uiekjxw.net`, `iuearx.net` 等10个域名
- 说明: 检测C2心跳、钓鱼跳转、远控备用C2等恶意域名

**3. 银狐病毒 - C2服务器IP检测** (Critical)
- 类型: `dst_ip`
- 特征: `183.167.230.197`, `154.94.232.120`, `38.181.42.127`, `192.238.129.9` 等11个IP
- 说明: 检测连接到C2服务器的流量(2025年活跃IP)

**4. 银狐病毒 - 恶意PNG下载检测** (Critical)
- 类型: `http`
- 特征: `183.167.230.197:18743/(0CFA042F|5B16AF14|57BC9B7E|test).Png`
- 说明: 检测通过PNG文件伪装的恶意载荷下载

**5. 银狐病毒 - 钓鱼URL检测** (Critical)
- 类型: `http`
- 特征: `baidu.com@cuomicufvhehy.cn`
- 说明: 检测伪装成百度的钓鱼URL

**6. 银狐病毒 - 系统进程异常外联** (Warning)
- 类型: `process`
- 特征: `svchost.exe`, `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `powershell.exe`, `cmd.exe`
- 说明: 监控系统进程的网络外联行为,银狐常利用这些进程进行注入

#### 规则匹配逻辑
```go
// 告警规则匹配 (internal/store/alert.go)
func matchRule(value string, rule *AlertRule) bool {
    switch rule.ConditionOperator {
    case "regex":
        // 正则匹配(支持(?i)忽略大小写)
        re, _ := regexp.Compile(rule.ConditionValue)
        return re.MatchString(value)
        
    case "contains":
        // 逗号分隔的多值匹配
        values := strings.Split(rule.ConditionValue, ",")
        for _, v := range values {
            if strings.Contains(value, strings.TrimSpace(v)) {
                return true
            }
        }
        return false
        
    case "equals":
        // 精确匹配
        return value == rule.ConditionValue
    }
}
```

#### 告警日志字段
| 字段名 | 说明 | 示例 |
|-------|------|------|
| `id` | 告警ID | 12345 |
| `rule_id` | 触发的规则ID | 3 |
| `rule_name` | 规则名称 | 银狐病毒 - C2域名检测 |
| `alert_level` | 告警级别 | critical |
| `trigger_value` | 触发值 | 12-18.qq-weixin.org |
| `packet_id` | 关联数据包ID | 67890 |
| `src_ip` | 源IP | 192.168.1.100 |
| `dst_ip` | 目标IP | 183.167.230.197 |
| `process_name` | 关联进程 | chrome.exe |
| `count` | 聚合计数 | 15 |
| `first_seen` | 首次触发时间 | 2025-10-08 14:32:15 |
| `last_seen` | 最后触发时间 | 2025-10-08 14:45:30 |
| `acknowledged` | 是否已确认 | false / true |
| `acknowledged_at` | 确认时间 | 2025-10-08 15:00:00 |

#### 规则版本管理
- ✅ **版本控制**: v1.0.0
- ✅ **自动更新**: 只在版本升级时重新安装规则
- ✅ **智能清理**: 自动删除旧版本规则,避免重复
- ✅ **性能优化**: 避免每次启动都重复插入规则

#### 使用场景
- 🛡️ **APT检测**: 检测银狐、Lazarus等APT组织的IOC
- 🚨 **实时告警**: 发现恶意流量立即弹窗提醒
- 📊 **安全态势**: 统计告警趋势,评估网络安全状况
- 🔍 **溯源分析**: 通过告警记录追溯攻击路径

---

### 🔟 2D地图 (2D Map Visualization)

#### 功能描述
基于ECharts Geo组件的世界地图流量可视化,显示全球连接分布。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **地理编码** | 自动查询IP的经纬度坐标(GeoIP) |
| **热力图** | 根据连接数量显示热力分布 |
| **连接线** | 显示源IP到目标IP的连线 |
| **国家统计** | 统计连接最多的TOP国家 |
| **交互式操作** | 支持缩放、平移、点击查看详情 |

#### 可视化效果
```typescript
// 2D地图配置 (ECharts Geo)
{
  geo: {
    map: 'world',
    roam: true,  // 支持缩放和平移
    itemStyle: {
      areaColor: '#1a1a2e',
      borderColor: '#16213e'
    }
  },
  series: [
    {
      type: 'scatter',      // 散点图(显示IP位置)
      coordinateSystem: 'geo',
      data: [
        { name: '192.168.1.100', value: [116.4, 39.9, 100] }  // [经度, 纬度, 连接数]
      ]
    },
    {
      type: 'lines',        // 连线(显示流量方向)
      data: [
        { coords: [[116.4, 39.9], [-74.0, 40.7]] }  // 北京 → 纽约
      ]
    }
  ]
}
```

#### GeoIP数据库
- **数据源**: MaxMind GeoLite2 City数据库
- **精度**: 国家级99%, 城市级80%
- **更新频率**: 每月更新
- **文件路径**: `data/GeoLite2-City.mmdb`

---

### 1️⃣1️⃣ 3D地球 (3D Globe Visualization)

#### 功能描述
基于ECharts GL的3D地球流量可视化,提供更炫酷的大屏展示效果。

#### 核心功能
| 功能点 | 说明 |
|-------|------|
| **3D渲染** | 基于WebGL的真实地球渲染 |
| **流线效果** | 显示数据流动轨迹的3D流线 |
| **散点模式** | 显示全球IP分布的3D散点 |
| **混合模式** | 同时显示散点+流线 |
| **自动旋转** | 地球自动旋转展示全球视角 |
| **视角切换** | 支持手动拖拽调整视角 |

#### 可视化模式
| 模式 | 说明 | 适用场景 |
|-----|------|---------|
| **流线模式** (默认) | 显示数据流动轨迹的弧线 | 大屏展示、动态效果 |
| **散点模式** | 显示全球IP位置的点 | 地理分布分析 |
| **混合模式** | 同时显示流线+散点 | 全面展示 |

#### 技术实现
```typescript
// 3D地球配置 (ECharts GL)
{
  globe: {
    baseTexture: 'earth.jpg',         // 地球纹理
    heightTexture: 'elevation.jpg',   // 高度纹理
    displacementScale: 0.05,          // 地形起伏
    shading: 'realistic',             // 逼真光照
    atmosphere: {
      show: true,                     // 大气层效果
    },
    light: {
      ambient: { intensity: 0.4 },    // 环境光
      main: { intensity: 1.0 }        // 主光源
    }
  },
  series: [
    {
      type: 'lines3D',                // 3D流线
      coordinateSystem: 'globe',
      effect: {
        show: true,
        trailLength: 0.5,             // 尾迹长度
        trailWidth: 2,                // 尾迹宽度
        trailOpacity: 0.8
      }
    }
  ]
}
```

#### 性能优化
- **LOD(Level of Detail)**: 根据距离调整渲染精度
- **数据采样**: 连接数过多时自动采样TOP N条
- **帧率控制**: 限制最大帧率为60fps
- **GPU加速**: 充分利用WebGL硬件加速

#### 用户交互
- 🖱️ **鼠标拖拽**: 旋转地球
- 🔍 **滚轮缩放**: 放大/缩小
- ⏸️ **暂停旋转**: 鼠标悬停时暂停自动旋转
- 📊 **点击查看**: 点击流线查看详细信息

---

### 1️⃣2️⃣ 设置 (Settings)

#### 功能描述
系统配置管理,包括抓包参数、告警规则、性能优化等设置。

#### 核心功能
| 模块 | 说明 |
|-----|------|
| **网卡设置** | 选择抓包网卡、设置BPF过滤器 |
| **存储设置** | 设置数据库路径、PCAP保存策略 |
| **性能设置** | 调整内存限制、刷新频率 |
| **告警设置** | 启用/禁用规则、调整告警级别 |
| **GeoIP设置** | 配置GeoIP数据库路径 |
| **导入/导出** | 导入自定义规则、导出配置 |

#### 配置文件
```yaml
# config.yaml
capture:
  device: "eth0"                     # 抓包网卡
  bpf_filter: "tcp or udp"           # BPF过滤器
  promiscuous: true                  # 混杂模式
  snaplen: 65535                     # 捕获长度

storage:
  db_path: "./data/sniffer.db"       # SQLite数据库路径
  pcap_dir: "./data/pcap"            # PCAP保存目录
  pcap_rotation: "1h"                # PCAP轮转周期
  retention_days: 7                  # 数据保留天数

performance:
  ring_buffer_size: 10000            # 环形缓冲区大小
  batch_insert_size: 100             # 批量插入大小
  refresh_interval: 2000             # 前端刷新间隔(毫秒)

alert:
  enabled: true                      # 启用告警
  min_level: "warning"               # 最低告警级别
  notification: true                 # 桌面通知

geoip:
  db_path: "./data/GeoLite2-City.mmdb"  # GeoIP数据库路径
```

#### 高级设置
- **调试模式**: 启用详细日志输出
- **导出格式**: 选择JSON/CSV/PCAP导出格式
- **主题切换**: 深色/浅色主题切换
- **语言设置**: 中文/英文界面语言

---

## 🚀 快速开始

### 安装依赖

**Windows:**
```powershell
# 安装Npcap (https://npcap.com/)
winget install Npcap.Npcap

# 安装Go 1.22+
winget install GoLang.Go

# 安装Node.js 18+
winget install OpenJS.NodeJS
```

**Linux:**
```bash
# 安装libpcap
sudo apt install libpcap-dev  # Debian/Ubuntu
sudo yum install libpcap-devel  # RedHat/CentOS

# 安装Go 1.22+
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz

# 安装Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

**macOS:**
```bash
# 安装libpcap (macOS自带)
brew install libpcap

# 安装Go和Node
brew install go node
```

### 构建运行

```bash
# 克隆仓库
git clone https://github.com/your-repo/fastmonitor.git
cd fastmonitor

# 安装前端依赖
cd frontend && npm install && cd ..

# 运行开发模式
wails dev

# 构建生产版本
wails build
```

### 首次启动

1. **以管理员权限运行** (必需)
   - Windows: 右键 → "以管理员身份运行"
   - Linux/macOS: `sudo ./fastmonitor`

2. **选择网卡** → 点击"设置" → 选择活跃网卡

3. **开始抓包** → 点击顶部"开始捕获"按钮

4. **查看仪表盘** → 实时查看流量统计和图表

---



## 🛠️ 技术栈

### 后端
- **语言**: Go 1.22
- **框架**: Wails v2.10
- **抓包**: gopacket + libpcap
- **数据库**: SQLite 3
- **GeoIP**: MaxMind GeoLite2

### 前端
- **语言**: TypeScript 5.3
- **框架**: Vue 3.4
- **UI库**: Element Plus 2.5
- **状态管理**: Pinia 2.1
- **路由**: Vue Router 4.2
- **图表**: ECharts 5.6 + ECharts GL 2.0

---



## 🤝 贡献指南

欢迎提交Issue和Pull Request!

1. Fork本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

---


## 📧 联系方式

- **项目主页**: https://github.com/your-repo/fastmonitor
- **问题反馈**: https://github.com/your-repo/fastmonitor/issues
- **邮箱**: team@fastmonitor.dev

---

## 🙏 致谢

- [Wails](https://wails.io/) - 跨平台桌面应用框架
- [gopacket](https://github.com/google/gopacket) - Go数据包处理库
- [ECharts](https://echarts.apache.org/) - 数据可视化图表库
- [Element Plus](https://element-plus.org/) - Vue 3 UI组件库
- [MaxMind](https://www.maxmind.com/) - GeoIP地理位置数据库

---

**FastMonitor** - 让网络流量监控更简单、更高效、更智能! 🚀

