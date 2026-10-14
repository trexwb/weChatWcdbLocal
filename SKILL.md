---
name: wechat-wcdb-local
description: 微信桌面版 4.x（WCDB/SQLCipher4）本地数据库离线解密与聊天记录提取的 Node.js 跨平台工具（Windows/macOS），可作为 WorkBuddy / CodeBuddy / Qoder / Claude 等各类 agent 的技能从 GitHub 直接安装。当用户需要从自己设备一键解密微信 WCDB 加密数据库、提取 Msg_ 表聊天消息、获取微信数据库密钥（Windows 内存 dump 或扫描 / macOS frida），或生成聊天记录 HTML 报告时使用本技能。
agent_created: true
---

# 微信 WCDB 本地解密与消息提取（Node.js 跨平台）

## 目的

把微信桌面版 4.x 的本地 WCDB/SQLCipher4 加密数据库在**本机离线**解密，并提取聊天记录。提供 Windows 与 macOS 统一的密钥模型与纯 JS 解密后端，无需任何原生编译，两个平台行为一致。

## 何时使用

- 用户想解密自己电脑上的微信数据目录（`db_storage` 下的 `*.db`）。
- 用户想提取某个会话（`Msg_<md5(username)>` 表）的聊天消息。
- 用户需要获取微信数据库密钥：Windows 从进程内存 dump 提取，macOS 用 frida 抓取 `CCKeyDerivationPBKDF` 的 passphrase。
- 用户想把提取结果生成可读报告，或导出给其它应用消费：`html`（人看）/ `md`（文档、LLM）/ `json`（程序解析），可一次同时产出；也可用 `--template` 挂自定义模板。

## 权限与风险声明（供宿主弹窗确认）

本技能在执行前需要用户知情同意。**宿主 agent（WorkBuddy / CodeBuddy / Qoder / Claude 等）应在弹窗中向用户展示下列清单**，用户点「同意」后才继续：

- **读取本地微信数据目录**：`db_storage` 下的 `message_*.db / contact.db / session.db`（Windows 由 `%APPDATA%\Tencent\xwechat\config\*.ini` 定位，macOS 在 `~/Library/Containers/com.tencent.xinWeChat/...`）。
- **读取微信进程内存**（可选，仅在用户显式要求自动取密钥时）：Windows 走 `--allow-memory-scan`（调 `Kernel32` 读进程内存）；macOS 走 `--mac-frida`（frida 附加微信进程拦截 `CCKeyDerivationPBKDF`）。
- **本机执行 Node 命令**并**写出明文数据库与结果文件**：`plain/*.plain.db`、`messages.json`，以及报告文件 `report.html` / `report.md` / `report.json`（按所选格式生成）。
- **不联网、不上传**：全程本机离线处理，任何数据不发送到外部。
- **敏感提示**：产物中包含明文聊天记录与数据库密钥（`keys.json` / passphrase），使用完毕后应删除。

前置原则：**仅用于读取用户自己设备上的微信数据**（本地取证 / 备份 / 归档），不得用于未经授权访问他人数据，需遵守当地法律法规与微信用户协议。

## 一键流水线（授权通过后调用）

用户同意授权后，运行**一条命令**即可完成「取密钥 → 解密 → 提取 → 报告」：

```bash
# 已知 passphrase（最通用）
node bin/wcdb.js pipeline --username wxid_目标 --self-wxid wxid_本人 --key <passphrase_hex>

# Windows：从内存 dump 取密钥
node bin/wcdb.js pipeline --username wxid_目标 --dump wcdb_blob.bin

# macOS：frida 抓取（需重签名微信 + root，在启动瞬间抓）
sudo node bin/wcdb.js pipeline --username wxid_目标 --mac-frida
```

输出：`messages.json`（结构化消息）与报告文件（默认 `report.html`，加 `-f html,md,json` 可同时得到 `report.md` / `report.json`；各文件路径会在结束时打印）。

若生成了 `md` / `json` 报告，agent 应在回复中**明确告知用户这些文件的路径**，便于用户用其它应用直接打开或二次加工。

若密钥来源缺失或平台不匹配，命令会抛出**含可执行提示**的异常（如「请提供 --key / --dump / --keys；macOS 可用 --mac-frida，Windows 可用 --allow-memory-scan」），agent 应把该提示原样回传给用户。

## 打包的工具

本技能在仓库根目录附带一个完整的 Node.js 工具（`package.json` + `bin/wcdb.js` + `src/`）。核心模块：

- `src/constants.js` — XOR 掩码、zstd magic、表名函数、参数常量
- `src/platform.js` — Windows/macOS 数据目录自动定位
- `src/zstd.js` — zstd 解压（`@foxglove/wasm-zstd`，wasm 无原生编译）
- `src/keyExtract.js` — 密钥提取：Win 内存扫描 / dump / 手动
- `src/macKeyFrida.js` — macOS frida 抓 passphrase
- `src/decrypt.js` — passphrase + 每库 salt → enc_key → 解密调度
- `src/wcdbDecode.js` — 纯 JS WCDB/SQLCipher4 页面解码（AES-256-CBC + HMAC-SHA512）
- `src/extract.js` — 消息提取（zstd / local_type / real_sender_id 反推）
- `src/report.js` — 报告输出层：单/多格式分发（html/md/json）+ 自定义模板载入
- `src/templates/` — 报告模板：注册中心 `index.js`、`helpers.js`（转义 / 昵称 / 归一化）、`html.js`、`markdown.js`、`json.js`

详细的加密格式、密钥模型与已知陷阱见 `references/wcdb-crypto.md`。

## 使用流程

### 1. 安装附带工具

在仓库根目录运行：

```bash
npm install
# 可选：macOS frida 抓密钥（仅 Mac 需要）
npm install frida
# 可选：解密回退后端（通常不需要，纯 JS 已覆盖绝大多数场景）
npm install sqlcipher
```

解密是纯 JS 实现，无需任何原生编译；`better-sqlite3` 自带预编译二进制，一般装完即用。

### 2. 获取密钥（passphrase）

- 已知密钥：直接用 `--key <hex>`。
- Windows 内存 dump（最稳妥，跨平台）：`node bin/wcdb.js key --dump wcdb_blob.bin -o keys.json`
- Windows 实时扫描（实验性，需 `--allow-memory-scan`）：`node bin/wcdb.js key --allow-memory-scan -o keys.json`
- macOS frida（需重签名微信 + root）：`sudo node bin/wcdb.js key --mac-frida -o keys.json`

### 3. 解密数据库

```bash
node bin/wcdb.js decrypt --dir <db_storage路径> --keys keys.json --out plain/
# 或已知 passphrase 时
node bin/wcdb.js decrypt --dir <db_storage路径> --key <passphrase_hex> --out plain/
```

解密默认走纯 JS 后端；若个别微信版本异常，加 `--backend sqlcipher` 回退到原生模块。

### 4. 提取消息

```bash
node bin/wcdb.js extract --db plain/message_0.plain.db --username wxid_xxxx --self-wxid wxid_you --out messages.json
```

### 5. 生成报告

```bash
# 只出 HTML
node bin/wcdb.js report --in messages.json --out report.html

# 一次同时产出 HTML / Markdown / JSON（供其它应用直接用），运行结束会打印各文件路径
node bin/wcdb.js report --in messages.json -f html,md,json
```

格式：`html` 给人看；`md` 贴文档 / 喂 LLM；`json` 带 `meta` 与 `sender_name`，供程序解析。三种格式共用同一份归一化数据，字段语义一致。需要别的格式时用 `--template <file.js>`（模块导出 `(data, ctx) => string`）。

### 6. 自测

```bash
npm test
```

## 跨平台兼容性

本技能**同时支持 Windows 与 macOS**，关键保证如下：

- **平台探测**：`detectPlatform()` 用 `process.platform` 区分 `win32` / `darwin` / 其他，数据目录定位各自独立实现（`resolveWindowsDataDir` 读 `%APPDATA%`+`.ini`，`resolveMacDataDir` 扫 `~/Library/Containers/com.tencent.xinWeChat/...`）。
- **平台代码隔离**：Windows 实时内存扫描（`Kernel32.dll` + koffi）与 macOS frida 抓取互相隔离，未命中对应平台时给出明确指引而非崩溃；`koffi` / `frida` 均为**惰性 `require`**，不会在另一平台加载期报错。
- **路径跨平台**：临时文件统一用 `os.tmpdir()` + `path.join` 构造（如 passphrase 落盘 `wxdb/passphrase.hex`），不写死 `/tmp`，Windows 上自动落到 `AppData\Local\Temp`。
- **依赖双平台可用**：`@foxglove/wasm-zstd`（wasm 无原生）、`better-sqlite3`（有 win/mac 预编译）、`commander`（纯 JS）、`koffi`（有 win/mac 预编译）均可在两系统 `npm install`；`sqlcipher` 仅为 `optionalDependencies` 回退；`frida` 仅 macOS 按需 `npm install frida`。
- **CLI 跨平台**：`bin/wcdb.js` 用 `#!/usr/bin/env node`，Windows 下 npm 自动生成 `.cmd` 包装，`wcdb` 命令可用。

## 跨 agent 兼容性

本技能采用**单一通用 `SKILL.md`**（遵循 Agent Skills 标准：YAML frontmatter 的 `name` + `description`，Markdown 正文），因此可被各类 agent 客户端识别：

| Agent | 安装位置（手动放置时） |
|-------|----------------------|
| WorkBuddy | `~/.workbuddy/skills/wechat-wcdb-local/` |
| CodeBuddy | `~/.codebuddy/skills/wechat-wcdb-local/` |
| Claude Code | `~/.claude/skills/wechat-wcdb-local/` |
| Qoder | 其技能目录，或从 GitHub URL 直接安装 |

- **从 GitHub 直接安装**：在客户端的「技能中心 / 从 URL 安装」粘贴本仓库地址即可，客户端会读取根目录 `SKILL.md`。
- frontmatter 中的 `agent_created` 为 WorkBuddy 专有字段，其他 agent 会忽略未知字段，不影响加载。
- 技能目录名建议与 `name: wechat-wcdb-local` 保持一致，便于管理。

## 关键注意事项

- **法律与隐私**：仅用于读取本人设备数据，遵守当地法律法规与微信用户协议；全程本机处理，数据不上传。
- **macOS 无 `Config.Cipher`**：Mac 版微信只有 frida 路径，详见 `references/wcdb-crypto.md`。
- **未真机验证项**：纯 JS 对真实微信 4.x `.db` 解密、Windows 实时内存扫描、macOS frida 抓取均依赖真实环境，需在真机确认。
- **local_type 取低 32 位**；群消息发送者由 `wxid_xxx:\n` 前缀反推；`real_sender_id` 每个 `message_N.db` 独立，库内无映射表。
- **重签名保留 sandbox**：删掉 `com.apple.security.app-sandbox` 会让微信切到另一数据目录，读不到已有记录。
