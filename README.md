# CyberMap MCP

聚合 10 个网络空间测绘/威胁情报平台的 MCP Server。修改记录见 [CHANGELOG.md](CHANGELOG.md)。

| 引擎 | 用途 | 环境变量 | 申请地址 |
|---|---|---|---|
| Fofa | 资产搜索 | `FOFA_EMAIL`, `FOFA_KEY` | https://fofa.info/userInfo |
| Hunter(奇安信) | 资产搜索 | `HUNTER_KEY` | https://hunter.qianxin.com/home/personalInfo?to=api |
| Quake(360) | 资产搜索 | `QUAKE_KEY` | https://quake.360.net/quake/#/personal?tab=message |
| Shodan | 资产搜索 | `SHODAN_KEY` | https://account.shodan.io/ |
| Censys | 资产搜索 | `CENSYS_ID`, `CENSYS_SECRET` | https://search.censys.io/account/api |
| ZoomEye(知道创宇) | 资产搜索 | `ZOOMEYE_KEY` | https://www.zoomeye.org/profile |
| 0.zone(零零信安) | 资产搜索 | `ZONE0_KEY` | https://0.zone/apply |
| DayDayMap | 资产搜索 | `DAYDAYMAP_KEY` | https://www.daydaymap.com/help/document?type=api-auth |
| ThreatBook(微步) | IP 情报 | `THREATBOOK_KEY` | https://x.threatbook.com/v5/myApi |
| VirusTotal | IP/域名情报 | `VT_KEY` | https://www.virustotal.com/gui/ (个人 API key) |

## 工具

- `map_search(query, engines?, limit=20, page=1)` — 一次查询多个资产测绘引擎，
  结果按 `(ip, port, host/domain, protocol)` 去重合并，每条带 `sources` 字段
  标明来源引擎；单引擎报错不影响其他引擎。
  `query` 可以是字符串（原样广播给所有选中引擎）或字典 `{"fofa": "app=\"Tomcat\"",
  "shodan": "http.component:tomcat"}`（各引擎用各自语法，跨 DSL 混查时推荐）。
- `host_intel(target)` — 单个 IP/域名情报：ThreatBook IP 信誉 + VirusTotal 报告。
- `github_search(query, type=code|repositories|issues, limit=20)` — GitHub 搜索：
  code 搜泄露/dork（需要 `GITHUB_TOKEN`），repositories/issues 无需 token。
- `cve_search(query, limit=20)` — NVD 漏洞库：传 CVE 编号精确查（`CVE-2021-44228`）
  或关键词模糊查（`log4j`）；`NVD_API_KEY` 可选，配置后提速率上限。
- `engine_status()` — 列出各引擎 key 配置状态，配 key 前先调它。

## 运行

单文件静态二进制，无运行时依赖。从源码构建或下载 Release 预编译版：

```bash
go build -o cybermap-mcp .                  # 需要 Go 1.24+

export FOFA_EMAIL=... FOFA_KEY=... HUNTER_KEY=...   # 按需配置，配几个用几个
./cybermap-mcp                                       # stdio（默认）
./cybermap-mcp -transport http -addr :8080           # Streamable HTTP
./cybermap-mcp -transport sse  -addr :8080           # SSE
```

客户端配置（Cursor / Claude Desktop / Cline 等）：

```json
{
  "mcpServers": {
    "cybermap": {
      "command": "cybermap-mcp",
      "env": {
        "FOFA_EMAIL": "you@example.com",
        "FOFA_KEY": "…",
        "HUNTER_KEY": "…",
        "QUAKE_KEY": "…",
        "SHODAN_KEY": "…",
        "CENSYS_ID": "…",
        "CENSYS_SECRET": "…",
        "ZOOMEYE_KEY": "…",
        "ZONE0_KEY": "…",
        "DAYDAYMAP_KEY": "…",
        "THREATBOOK_KEY": "…",
        "VT_KEY": "…"
      }
    }
  }
}
```

## 网络传输（http / sse）

http/sse 模式监听 TCP 端口，**务必配置 token**，否则能访问端口的人都能白嫖你的引擎额度：

```bash
./cybermap-mcp -transport http -addr :8080 -token <随机长串>
# 或 CYBERMAP_TOKEN=<随机长串> cybermap-mcp -transport http
# 客户端请求头：Authorization: Bearer <token>
```

stdio 模式是本地进程通信，无需 token。

## 代理

访问 Shodan/Censys/VirusTotal 等境外平台时使用：

```bash
# 优先级：-proxy 参数 > CYBERMAP_PROXY > HTTP(S)_PROXY 环境变量
./cybermap-mcp -proxy socks5://127.0.0.1:1080
CYBERMAP_PROXY=http://127.0.0.1:7890 ./cybermap-mcp

# 按引擎路由：只有列出的引擎走代理，国内引擎直连
CYBERMAP_PROXY=... CYBERMAP_PROXY_ENGINES=shodan,censys,virustotal ./cybermap-mcp
```

tag 推送（`v*`）时 GitHub Actions 自动编译 linux/darwin/windows × amd64/arm64
二进制并上传到 Release（见 `.github/workflows/build.yml`）。

## 查询语法说明

各引擎 DSL 相近但不完全一致，`query` 会原样透传给每个引擎：

- Fofa / Hunter / Quake / DayDayMap 基本互通：`app="Tomcat" && country="CN"`、
  `domain="example.com"`、`ip="1.2.3.4/24"`
- Shodan：`http.component:tomcat country:CN`、`hostname:example.com`
- Censys v2：`services.service_name: HTTP and location.country: CN`
- ZoomEye：`app:"Tomcat" country:"CN"`
- 0.zone：`(company=xxx有限公司)||(title=xxx)`（查 site/信息系统）

## 已知配额约束（引擎侧限制，非本服务限制）

- Hunter: page_size ≤ 100；免费配额按积分扣
- 0.zone: 单页 ≤ 40 条，每日 ≤ 250 次查询，速率 ≤ 2 次/秒
- Censys v2 hosts/search 单页 ≤ 100
- Fofa 免费 key 仅支持第 1 页
