# SqlScout

`SqlScout` 是一个基于 `Montoya API 2026.4` 开发的 Burp Suite SQL 注入辅助检测插件，定位是“快速筛查 + 人工复核”的实战型工具。

它源于对早期 `xia SQL` 插件的重构，目前重点放在以下几个方向：

- 更清晰的 Montoya 架构
- 更稳的参数变异能力
- 更好的嵌套 JSON / URL 编码 JSON 支持
- 更可控的过滤与策略配置
- 更适合日常人工测试的结果展示

## 项目定位

`SqlScout` 不是一个“全自动确认漏洞”的重型扫描器，而是一个偏轻量、可控、适合 Burp 日常工作流的 SQL 注入辅助插件。

适合的使用场景：

- 在 `Proxy` / `Repeater` 中快速筛出可疑请求
- 对复杂参数结构做定向测试
- 结合人工经验观察报错、差异、延时和参数上下文
- 为后续手工验证或其他工具联动提供线索

## 当前功能

### 流量来源

- 支持监听 `Proxy`
- 支持监听 `Repeater`
- 支持右键菜单手动发送扫描

### 支持的参数类型

- URL Query 参数
- 常规 Body / Form 参数
- Cookie 参数
- JSON 参数
- 多层嵌套 JSON
- JSON 数组中的叶子值
- URL 编码后的 JSON 参数
- `multipart/form-data` 中的文本字段
- 隐藏参数追加 fuzz（当前以 URL/Form 请求为主）

### 参数处理能力

- 普通参数更新
- JSON 参数优先使用 Montoya 原生更新
- JSON 回退到基于偏移量的局部改写
- JSON 路径展示，如：
  - `items[0].id`
  - `commonDto[1].value`
- 请求高亮显示被修改的值
- URL 编码 JSON 的局部高亮

### 检测信号

- 报错特征命中
- 响应差异提示
- 响应相似度显示
- 时间延迟提示

### 判定等级

- `INFO`
- `SUSPECTED`
- `CONFIRMED`

当前规则说明：

- 只要命中 `Err`，即视为最高等级 `CONFIRMED`

### 参数上下文感知

当前已经具备基础分类能力：

- 通用参数
- 数值控制参数
- 排序控制参数

例如：

- `id / page / limit / offset / pageSize` 会被当作数值控制参数
- `sort / order / orderBy / direction` 会被当作排序参数

排序参数会自动使用更贴近 `ORDER BY` 场景的 payload；数值型参数会自动追加 `-1 / -0`。

### 过滤能力

- 域名白名单
- 域名黑名单
- 后缀过滤
- 静态资源跳过
- 图片响应识别跳过
- `multipart` 文件字段跳过策略

### Payload 能力

- 默认 payload 策略
- 自定义 SQL payload
- Payload 分组模式：
  - `auto`
  - `default`
  - `order`
  - `time`
  - `error`
  - `custom`

说明：

当前的 `Payload 分组` 更像“策略切换器”，还不是完整的多套 payload 库管理器。

### 响应比较能力

当前已引入独立的 `ResponseComparator`，用于替代过于粗糙的响应差异判断：

- 保留长度差作为快速信号
- 大响应按头尾片段比较
- 自动裁剪公共前后缀
- 在结果表中展示相似度

### UI 能力

主界面包含：

- 扫描结果表
- 参数尝试详情表
- Request / Response 查看器

设置页包含：

- 常规
- 白名单
- 黑名单
- 后缀过滤
- 隐藏参数
- Payload 分组
- 自定义 SQL
- 报错特征
- 日志

## 使用方式

### 被动监听

1. 打开 `SqlScout` 标签页
2. 在 `常规` 中开启 `Proxy` 或 `Repeater` 监听
3. 按需配置白名单、黑名单、后缀过滤
4. 浏览结果表并点击查看详情

### 手动右键发送

1. 在 `Proxy` 或 `Repeater` 中选中请求
2. 右键进入 `Extensions`
3. 点击 `Send to SqlScout`
4. 在 `SqlScout` 结果区查看测试情况

### 隐藏参数 fuzz

1. 打开 `隐藏参数` 页签
2. 输入隐藏参数名，支持按行或逗号分隔
3. 重新发送目标请求到 `SqlScout`

### 自定义 payload

1. 打开 `自定义 SQL`
2. 填写 payload 列表
3. 点击加载
4. 结合 `Payload 分组` 或 `自定义 payload` 选项使用

## 构建方式

环境要求：

- Java 17
- Maven 3.x
- Gradle 8.x（可选）

构建命令：

```bash
mvn clean package
```

或使用 Gradle：

```bash
gradle clean build
```

生成产物：

```text
target/SqlScout.jar
```

Gradle 产物：

```text
build/libs/SqlScout.jar
```

## GitHub Actions

项目已包含 GitHub Actions 自动构建流程：

- 触发条件：
  - push 到 `main` 或 `master`
  - Pull Request
  - 手动触发 `workflow_dispatch`
- 构建环境：
  - Java 17
  - Gradle 8.10.2
- 产物：
  - `build/libs/SqlScout.jar`

工作流文件位置：

```text
.github/workflows/build.yml
```

## 加载到 Burp Suite

1. 打开 Burp Suite
2. 进入 `Extensions`
3. 添加构建后的 `target/SqlScout.jar`
4. 加载成功后会看到 `SqlScout` 标签页

## 当前实现边界

虽然这版已经可用，但还有一些边界需要明确：

- 不是全自动漏洞确认器
- GraphQL 专项扫描尚未实现
- JSON 隐藏参数深度追加仍然保守
- Payload 分组还没有演进成完整的多组 payload 管理系统
- 判定规则还在持续迭代

如果你准备把它放到 GitHub 上，建议把项目定位写成：

> 面向 Burp 日常工作流的 SQL 注入辅助检测与参数变异插件

这个定位比“自动化 SQL 注入扫描器”更准确，也更符合当前实现。

## 项目结构

当前有效代码：

```text
src/main/java
```

保留的旧版反编译参考代码：

```text
src/burp
```

后续开发计划：

```text
REFACTOR_PLAN.md
```

## 后续方向

目前已经完成的重构重点包括：

- Montoya API 入口迁移
- 参数变异模块拆分
- JSON / URL 编码 JSON 支持
- 黑白名单和后缀过滤配置化
- 隐藏参数 fuzz
- Payload 分组初版
- 响应相似度比较器

后续更值得继续推进的方向：

- 更强的响应比较与误报控制
- 更完整的 Payload 分组管理
- GraphQL 支持
- 更细的排序/数值/结构化参数策略

## 参考项目

本项目在设计、重构思路和能力取舍上，参考了以下开源项目：

- [DetSql](https://github.com/saoshao/DetSql)
- [SQL-Injection-Scout](https://github.com/JaveleyQAQ/SQL-Injection-Scout)
- [XiaSQL_Plus](https://github.com/AnQuanPig/XiaSQL_Plus)
- [DouSql](https://github.com/darkfiv/DouSql)
