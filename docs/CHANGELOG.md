# Changelog

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

版本：`1.0.0` · 发布日期：2026-10-14 · 标签：`v1.0.0`

---

## [1.0.0] — 2026-10-14

首个正式版本。微信桌面版 4.x（WCDB / SQLCipher 4）本地数据库**离线**解密与聊天记录提取，Node.js 跨平台实现（Windows / macOS）。

完整发布说明见 [docs/releases/v1.0.0.md](releases/v1.0.0.md)。

### Added

- **统一密钥模型**：passphrase（32 字节）→ 每库独立 `enc_key = PBKDF2-HMAC-SHA512(passphrase, 该库首页 salt, 256000, 32)`，Windows 与 macOS 共用同一套解密路径。
- **纯 JS 解密后端**（`src/wcdbDecode.js`）：SQLCipher 4 页面格式（4096 页 / AES-256-CBC / HMAC-SHA512 / `mac_salt = salt XOR 0x3A`）逐页校验并解密，**无需任何原生编译**，两平台行为一致。实测吞吐约 150 MB/s。
- **sqlcipher 原生回退后端**（`src/decrypt.js`，可选依赖）：纯 JS 后端在个别微信版本异常时使用。
- **密钥获取四条通道**（`src/keyExtract.js`、`src/macKeyFrida.js`）：`--key` 手动传入、`--dump` 内存 dump 文件解析（跨平台）、`--allow-memory-scan` Windows 实时内存扫描（koffi 调 Kernel32，实验性、需显式开启）、`--mac-frida` macOS 启动瞬间拦截 `CCKeyDerivationPBKDF`。
- **数据目录自动定位**（`src/platform.js`）：Windows 读 `%APPDATA%\Tencent\xwechat\config\*.ini` 首行并回退默认路径；macOS 通配扫描沙盒版本目录。权限类失败（EPERM/EACCES）转为「开启完全磁盘访问权限」的可操作提示。
- **消息提取**（`src/extract.js`）：zstd 内容解压（wasm，指数扩容自适应目标容量）、`local_type` 低 32 位掩码、跨版本列名兼容映射、以 `wxid_xxx:\n` 前缀全表实证反推 `real_sender_id → wxid` 并判定「本人」。
- **HTML 报告**（`src/report.js`）：自包含单文件，全字段转义。
- **一键流水线**（`src/pipeline.js`）：`pipeline` 命令串起「取密钥 → 解密 → 提取 → 报告」；`resolveKeySource` 为无 I/O 纯函数并带平台互斥门禁（非 macOS 拒绝 `--mac-frida`、非 Windows 拒绝 `--allow-memory-scan`）。
- **CLI 五个子命令**：`key` / `decrypt` / `extract` / `report` / `pipeline`（`bin/wcdb.js`，commander）。
- **库方式入口**：`src/index.js` 汇总公共 API，加载期隔离平台原生依赖。
- **自测套件**：`test/selftest.js`，26 条断言，`npm test` 全绿。
- **Agent 技能封装**：根目录 `SKILL.md` 遵循 Agent Skills 标准，可从 GitHub 安装到 WorkBuddy / CodeBuddy / Qoder / Claude；含权限与风险声明，由宿主弹窗确认后再执行。

### Changed

- 跨平台兼容：临时文件路径不再写死 `/tmp`（改用 `os.tmpdir()`），补齐 `src/index.js`。
- 内存扫描默认关闭，必须显式 `--allow-memory-scan`；缺失密钥来源时抛出含可执行建议的异常而非静默失败。
- `pipeline` 的 `--keys` 仅在显式传入时生效，避免误用历史 `keys.json`。

### Security

- 解密全程本机进行，数据不上传；产物 `plain/`、`keys.json`、`messages.json`、`report.html` 已加入 `.gitignore`，防止把明文库与密钥提交进仓库。
- 报告生成对 content / sender / time / username / table 全字段 HTML 转义。
- 页面 HMAC 比较使用 `crypto.timingSafeEqual`。
- ⚠️ 本版本仍有两项密钥处置问题未修（密钥文件以 0644 落盘、`key` 命令把候选密钥原文打印到 stdout），详见已知问题 C-2 / M-5。在修复版本发布前，请按发布说明的「临时缓解措施」使用。

### 已知问题（本版本）

| 编号 | 影响 | 简述 |
|------|------|------|
| C-1 | 🔴 主路径阻塞 | `--dump` / `--allow-memory-scan` 的候选生成对每个字节偏移跑 4 次 PBKDF2（实测 81.75 ms/偏移）：1 MB dump 约 24 小时、64 MB 区域约 63 天，实际不可用 |
| C-2 | 🔴 密钥暴露 | passphrase 以 0644 落盘；文档主推的 sudo 调用会把 `os.tmpdir()` 重置为 `/tmp`，即写入同机可读的 `/tmp/wxdb/passphrase.hex`；`keys.json` 同为 0644 且落在工作目录 |
| C-3 | 🔴 契约失效 | `decrypt` 子命令未 `await`，统一错误提示与退出码被绕过，失败时打印裸栈 |
| M-1 | 🟠 内存 | 解密整库驻留（峰值约 2–3× 文件大小），2 GB 级 `message_*.db` 存在 OOM 风险 |
| M-2 | 🟠 SQL | `ATTACH DATABASE` 用字符串拼接输出路径，路径含单引号即失败（静态判断） |
| M-3 | 🟠 错误归因 | sqlcipher 未安装时，真实失败原因（passphrase 不对）被「缺原生模块」覆盖 |
| M-4 | 🟠 性能 | 同一消息表被全表扫描并解压两次 |
| M-5 | 🟠 密钥暴露 | `key` 命令把首个候选密钥原文输出到 stdout |
| M-6 | 🟠 资源 | frida 抓取成功后 90 秒定时器未清理，进程多存活至超时 |

完整定位（文件:行）与修复方案见 [docs/code-review.md](code-review.md) 与 [docs/code-review-fix-plan.md](code-review-fix-plan.md)。

### 兼容

- Node.js ≥ 16（开发/验证环境为 v24.21.0 / darwin arm64）
- 微信桌面版 4.x；`Config.Cipher` 符号与 XOR 掩码随版本可能变化
- 不支持媒体原文件（`.dat` 图片/视频/语音仍为密文）

### 未验证项

以下路径未在真实微信环境验证（开发环境无微信安装），首次部署请先在小样本上确认：纯 JS 后端对真实 4.x `.db` 的解密、Windows 实时内存扫描、macOS frida 抓取。

---

## 版本历史

| 版本 | 日期 | 说明 |
|------|------|------|
| [1.0.0] | 2026-10-14 | 首个正式版本 |
| 0.1.0 | 2026-10-14 | 内部开发版本（未发布，未打标签）；`package.json` / `package-lock.json` / `bin/wcdb.js` 已随本次发布统一为 1.0.0 |
