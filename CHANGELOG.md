# 更新日志

## v1.1.0 (2026-05-09)

### 架构重构
- **表格刷新机制重构**：将全量刷新（`fireTableDataChanged`）改为增量更新（`fireTableRowsInserted` / `fireTableRowsUpdated`），从根本上解决扫描运行中无法选中行查看详情的问题
- **事件模型细化**：`ScanLogStore` 的通用 `logChanged` 通知拆分为 `scanAdded` / `scanReplaced` / `attemptAdded` / `cleared` 四个细粒度事件
- **表格模型自维护数据**：`MainTableModel` 和 `AttemptTableModel` 各自维护独立数据列表，通过事件驱动增量同步，不再每次全量查询 Store

### Bug 修复
- **修复扫描中无法查看详情**：扫描状态为 `run...` 时点击左侧列表行，右侧 attempt 表格和请求/响应编辑器现在能正确实时显示扫描过程

### 新功能
- **速率控制**：新增可配置的并发线程数（1-20，默认 4）和请求间隔（0-10000ms，默认 0），设置面板「常规」页中的「速率控制」区块实时生效
- **黑名单列表化 UI**：黑名单从逗号分隔文本框改为列表添加/删除形式，支持逐条添加和批量选中删除
- **通配符匹配**：黑名单和白名单统一支持 `*` 通配符，对整个 URL 做全匹配，忽略大小写

### 改动文件
| 文件 | 改动说明 |
|------|---------|
| `DetectionEngine.java` | 可配置线程池 + 请求间隔延迟 + 通配符匹配 |
| `ExtensionState.java` | 新增 `concurrentScans` / `requestDelayMs` 配置项 |
| `ScanLogStore.java` | Listener 接口拆分为四个细粒度事件方法 |
| `SettingsRepository.java` | 持久化并发线程数和请求间隔 |
| `XiaSqlPanel.java` | 增量表格模型 + 速率控制 UI + 黑名单列表 UI |

### 通配符规则示例
| 规则 | 效果 |
|------|------|
| `*baidu.com*` | 匹配所有包含 baidu.com 的 URL |
| `*.baidu.com*` | 匹配 baidu.com 的所有子域名 |
| `https://api.example.com/*` | 仅匹配该域名下所有路径 |
