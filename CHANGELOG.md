# Changelog

## [0.0.1] - 2026-10-14

首个发布版本。

### Added
- `map_search` 的 `query` 支持字典形式 `{engine: query}`，每个引擎可使用各自 DSL
  （如 `{"fofa": "app=\"Tomcat\"", "shodan": "http.component:tomcat"}`），
  解决跨 DSL 混查时字符串广播导致 Shodan 等引擎静默返回无关结果的问题；
  字典 key 校验引擎名，与 `engines` 参数取交集
- `map_search` 工具描述内置 8 个搜索引擎的 DSL 速查表，模型无需外部文档
  即可按引擎正确构造查询
- 回归测试：Hunter page_size 向上取整 + 精确切片；query 字典路由/非法 key/空交集

### Fixed
- Hunter: `limit` 不在 `{1, 10, 20, 50, 100}` 时服务端返回 400「页大小不合法」；
  现向上取整到最近合法 page_size，取回后客户端切片到精确 `limit`
- Shodan: `limit` 参数此前被忽略（Shodan 固定 100 条/页、无 size 参数）；
  现客户端切片 `min(limit, 100)`
- 安全: httpx INFO 日志会打印完整请求 URL，泄露 query 参数中的 API key
  （Fofa/Hunter/Shodan）；现将 httpx 日志级别固定为 WARNING

### Chore
- `.gitignore` 忽略 `docs/superpowers/plans/`，并取消其 git 跟踪（本地保留）
