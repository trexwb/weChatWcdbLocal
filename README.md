# wechat-wcdb-node

微信桌面版 4.x（WCDB / SQLCipher）本地数据库**离线**解密与消息提取工具 —— **Node.js 跨平台实现（Windows / macOS）**。

> 仅用于读取**你自己**设备上的微信数据（本地取证 / 备份 / 归档）。请勿用于未经授权访问他人数据，并遵守当地法律法规与微信用户协议。全程本机处理，数据不上传。

本工具参考并整合了两个上游 Skill：

- `wechat-wcdb-local-extract`（Windows 内存 XOR + 内嵌 salt PBKDF2 方案）
- `wechat-chatlog-export-mac`（macOS frida 抓 `CCKeyDerivationPBKDF` + 确认的 SQLCipher4 参数）

---

## 工作原理（Win / Mac 统一模型）

微信 WCDB 本质是 **SQLCipher 4**。核心结论（已在 Mac 实测验证）：

1. **passphrase**：32 字节，是解密的总密钥。
   - Windows：从微信进程内存的 `Config.Cipher` blob（XOR 掩码解码）定位。
   - macOS：微信启动瞬间 frida 拦截 `CCKeyDerivationPBKDF`（rounds=256000、passwordLen=32 那次调用的第一个参数）。
   - 通用兜底：用 `--key <hex>` 直接提供。
2. **每库独立 enc_key**：每个 `.db` 首页前 16 字节是该库 salt，
   `enc_key = PBKDF2-HMAC-SHA512(passphrase, db_salt, 256000, 32)`。
3. **页面格式**（页大小 4096，AES-256-CBC）：
   - page 1：`[0:16] salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC-SHA512`
   - page N：`[0:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC-SHA512`
   - `mac_salt = salt XOR 0x3A`；`mac_key = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32)`
4. **解密后 page1 前 16 字节**还原为 `SQLite format 3\0`。

本工具把上述过程封装为 4 条子命令。**解密默认用纯 JS 实现的 WCDB/SQLCipher4 页面解码（AES-256-CBC + HMAC-SHA512），无需任何原生编译，Windows / macOS 行为一致**；仅当纯 JS 后端在个别微信版本上异常时才回退到 `sqlcipher` 原生模块。

## 目录结构

```
wechat-wcdb-node/
├── bin/wcdb.js            # CLI 入口（commander）
├── src/
│   ├── constants.js       # XOR 掩码 / zstd magic / Msg_ 表名 / 参数
│   ├── platform.js        # Win / Mac 数据目录自动定位
│   ├── zstd.js            # zstd 解压（@foxglove/wasm-zstd，wasm 无原生编译）
│   ├── keyExtract.js      # 密钥提取：Win 内存扫描 / dump / 手动
│   ├── macKeyFrida.js     # macOS frida 抓 passphrase
│   ├── decrypt.js         # passphrase + 每库 salt -> enc_key -> SQLCipher 解密
│   ├── extract.js         # 消息提取（zstd / local_type / real_sender_id 反推）
│   ├── report.js          # 报告输出层：单/多格式分发 + 自定义模板载入
│   └── templates/         # 报告模板注册中心
│       ├── helpers.js     # 转义 / 昵称解析 / 数据归一化（各格式共用）
│       ├── html.js        # HTML 模板
│       ├── markdown.js    # Markdown 模板
│       ├── json.js        # JSON 模板（带 meta 与昵称，供其它应用解析）
│       └── index.js       # 注册表 + 格式推断 + 扩展名改写
├── test/selftest.js       # 纯 JS 部分自测（zstd / 派生 / 提取 / 报告模板）
└── package.json
```

## 安装

```bash
cd wechat-wcdb-node
npm install                 # 装 wasm-zstd / better-sqlite3 / commander / koffi
```

- **解密是纯 JS 实现，无需编译**。`better-sqlite3` 有预编译二进制，一般装完即用。
- （可选）`sqlcipher` 原生模块作为解密回退后端：`npm install sqlcipher`（需 python3 + C 编译器）。
  注意：该 npm 包依赖一个 GitHub SSH 源，部分环境可能拉取失败；纯 JS 后端已覆盖绝大多数场景，通常不需要它。

### macOS 密钥抓取额外依赖（可选）

```bash
npm install frida          # 仅 macOS 用 frida 抓 passphrase 时需要
```

## 快速开始

### 通用（已知 passphrase 时）

```bash
# 1) 解密（直接给 passphrase；--dir 默认按平台自动定位 db_storage）
node bin/wcdb.js decrypt --dir /path/to/db_storage --key <passphrase_hex> --out plain/

# 2) 提取某会话
node bin/wcdb.js extract --db plain/message_0.plain.db --username wxid_xxxx --self-wxid wxid_you --out messages.json

# 3) 生成报告：HTML / Markdown / JSON 可一次同时产出
node bin/wcdb.js report --in messages.json -f html,md,json
#   -> report.html / report.md / report.json（路径会打印出来）
#   只要 Markdown：-o report.md 或 -f md
```

### Windows：自动提取密钥

```bash
# 先让微信登录运行；抓候选（实验性内存扫描需 --allow-memory-scan）
node bin/wcdb.js key --allow-memory-scan -o keys.json
# 或从一个内存 dump 文件提取（最稳妥，跨平台）
node bin/wcdb.js key --dump wcdb_blob.bin -o keys.json
# 然后解密（自动遍历 keys.json 候选）
node bin/wcdb.js decrypt --dir D:\xwechat_files\<wxid>\db_storage --keys keys.json --out plain/
```

### macOS：frida 抓 passphrase

前置（需本人操作，触碰系统安全边界）：

1. 复制并重签名微信到 `~/Applications/WeChat.app`，**保留 `com.apple.security.app-sandbox`**（否则微信切换数据目录）：
   ```bash
   cp -R /Applications/WeChat.app ~/Applications/
   codesign -d --entitlements :- /Applications/WeChat.app > ~/wx_ent_orig.plist
   # 用脚本生成带 get-task-allow 的新授权（删 application-identifier / team-identifier，保留 sandbox）
   codesign --force --deep --sign - --entitlements ~/wx_ent.plist ~/Applications/WeChat.app
   ```
2. 本机已 `npm install frida`。
3. **用 root 运行本命令，并在 90 秒内从 `~/Applications/WeChat.app` 启动微信**：
   ```bash
   sudo node bin/wcdb.js key --mac-frida -o keys.json
   # 抓到的 passphrase 同时写入 /tmp/wxdb/passphrase.hex
   node bin/wcdb.js decrypt --keys keys.json --out plain/
   ```
   > 注意：必须在微信「启动瞬间」attach，否则它启动后不再调用 PBKDF2；抓到后脚本会自动 `session.detach()`，避免微信变僵尸进程。

## 关键陷阱（移植自两个上游 Skill）

| 项 | 说明 |
|----|------|
| `local_type` 取低 32 位 | 高位是子类型标志，如 `244813135921 (0x3900000031) → 49` |
| zstd 内容 | `message_content` / `compress_content` 可能以 `28 b5 2f fd` 开头，需解压 |
| `real_sender_id` 反推 | 每个 `message_N.db` 独立本地索引，库内无映射表；用「`wxid_xxx:\n` 前缀」全表扫描实证构建 `{local_id → wxid}`；无前缀且无映射 = 本人 |
| Mac 无 `Config.Cipher` | `com.Tencent.WCDB.Config.Cipher` 在 Mac 版不存在，只有 `Tokenize / ScalarFunction`，故 Mac 必须用 frida |
| salt 附近搜密钥行不通 | 密钥不在 salt ±4KB 内，别在内存里搜 salt 定位密钥 |
| 重签名保留 sandbox | 删掉 `com.apple.security.app-sandbox` 会让微信切到另一数据目录，读不到已有记录 |
| 表名 bytes 问题 | `Msg_<md5(username)>`；本工具用 better-sqlite3 直读，天然处理字符串列 |

## 验证状态（诚实说明）

**已通过自测（`npm test`，17/17 通过）**：
- zstd 解压往返
- `Msg_` 表名 = `Msg_` + md5(username)
- XOR 掩码编解码往返、`collectCandidates` 能回收嵌入的 32B 密钥
- `deriveEncKey`：passphrase + 每库 salt 派生 enc_key，稳定且每库独立
- **纯 JS WCDB 页面解码往返**（AES-256-CBC + HMAC-SHA512 + 每页 IV），且错误密钥触发 HMAC 校验失败
- 消息提取全流程（合成明文库）：zstd 内容、`local_type` 低 32 位、群前缀解析、`real_sender_id` 反推、「本人」判定

**未经真机验证（本环境无微信安装）**，需你在真实设备上确认：
- 纯 JS 解码对真实微信 4.x `.db` 的解密（参数按实测 SQLCipher4 设定；如个别版本异常可切 `--backend sqlcipher`）
- Windows 实时内存扫描（koffi 调用 `OpenProcess/ReadProcessMemory/VirtualQueryEx`）
- macOS frida 抓取 passphrase（依赖重签名微信 + root + 启动时机）

## 已知限制

- 仅支持微信桌面版 4.x；微信版本升级可能改变 `Config.Cipher` 或相关函数符号。
- 媒体原文件（图片/视频/语音的 `.dat`）仍是密文，不在本工具范围。
- Windows 实时扫描与 macOS frida 均触碰系统安全机制，需相应权限。

## 作为各 agent 的技能安装（GitHub）

本仓库根目录的 `SKILL.md` 遵循 **Agent Skills 标准**（`name` + `description` frontmatter + Markdown 正文），可被各类 agent 客户端识别。推送到 GitHub 后即可直接安装。

**方式 A：客户端内置「从 URL 安装技能」（推荐）**

在客户端的技能中心 / 安装入口粘贴本仓库的 GitHub 地址，客户端会读取根目录 `SKILL.md` 完成安装：

| Agent | 说明 |
|-------|------|
| WorkBuddy | 技能中心粘贴仓库地址 |
| CodeBuddy | 技能中心粘贴仓库地址 |
| Qoder | 技能中心粘贴仓库地址 |
| Claude Code | 支持 Agent Skills，粘贴仓库地址或克隆到技能目录 |

**方式 B：手动放置（等价）**

```bash
git clone <本仓库地址> <目标技能目录>/wechat-wcdb-local
cd <目标技能目录>/wechat-wcdb-local && npm install
```

`<目标技能目录>` 按客户端取：

| Agent | 用户级目录 | 项目级目录 |
|-------|-----------|-----------|
| WorkBuddy | `~/.workbuddy/skills/` | `.workbuddy/skills/` |
| CodeBuddy | `~/.codebuddy/skills/` | `.codebuddy/skills/` |
| Claude Code | `~/.claude/skills/` | `.claude/skills/` |
| Qoder | 其技能目录（或用方式 A） | 同左 |

安装后在对话中提及「解密微信数据库 / 提取微信聊天记录」等意图，技能即被触发；客户端会先弹出**权限确认窗**，用户同意后自动执行。

> 技能目录名建议与 `SKILL.md` 中 `name: wechat-wcdb-local` 保持一致，便于管理。
> frontmatter 的 `agent_created` 是 WorkBuddy 专有字段，其他 agent 会忽略，不影响加载。

## 一键流水线（授权后）

用户同意授权后，一条命令完成「取密钥 → 解密 → 提取 → 报告」：

```bash
# 已知 passphrase
node bin/wcdb.js pipeline --username wxid_目标 --self-wxid wxid_本人 --key <passphrase_hex>

# Windows：内存 dump 取密钥
node bin/wcdb.js pipeline --username wxid_目标 --dump wcdb_blob.bin

# macOS：frida 抓取（需重签名微信 + root）
sudo node bin/wcdb.js pipeline --username wxid_目标 --mac-frida
```

产出 `messages.json`，报告默认 `report.html`；加 `-f html,md,json` 即可一次拿到 Markdown / JSON，运行结束会打印每个文件的路径。密钥来源缺失或平台不匹配时，会抛出含可执行提示的异常（agent 应原样回传用户）。

## 报告格式与模板

三种内置格式由 `src/templates/` 提供，共用同一份归一化数据（昵称解析、`create_time_iso` 补全、`meta` 统计），因此字段语义一致：

| 格式 | 说明 | 典型用途 |
|------|------|----------|
| `html` | 自包含 HTML，CSS 内联 | 人看：浏览器直接打开、截图 |
| `md` | Markdown：标题 + 表格（单元格内 `\|` 与换行已转义） | 贴文档、喂 LLM、转 HTML/PDF |
| `json` | 结构化：`meta` / `selfWxid` / `contacts` / `chats[]`，每条消息带 `sender_name` | 其它应用直接解析 |

```bash
# 只出 Markdown（扩展名自动推断格式）
node bin/wcdb.js report --in messages.json -o report.md

# HTML 与 JSON 同时产出，并通知各自路径
node bin/wcdb.js report --in messages.json -f html,json

# json 压成单行
node bin/wcdb.js report --in messages.json -f json --compact

# 流水线里同样生效
node bin/wcdb.js pipeline --username wxid_目标 --key <hex> -f html,md,json
```

输出示例：

```
报告已生成（3 个文件）：
  HTML -> report.html
  MD -> report.md
  JSON -> report.json
```

### 自定义模板

不想改仓库代码也能扩展新格式（csv / txt / 推送给下游的 JSON 方言等）：写一个 JS 模块，导出 `(data, ctx) => string`，用 `--template` 指定即可。

```js
// my-tpl.js：ctx 提供 escapeHtml / escapeMdCell / resolveName / normalizeReport 等辅助
module.exports = (data, ctx) =>
  data.chats
    .map((c) => c.messages.map((m) => `${ctx.displayTime(m)}\t${m.sender}\t${m.content}`).join('\n'))
    .join('\n');
```

```bash
node bin/wcdb.js report --in messages.json --template ./my-tpl.js -o out.txt
```

以库方式使用时：`renderReport(data, 'md')` / `writeReports('report.html', data, ['html','md','json'])` / `renderWithTemplate(path, data)`。

## License

MIT（个人在自有数据上使用）。
