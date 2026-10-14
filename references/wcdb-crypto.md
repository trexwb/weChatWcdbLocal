# 微信 WCDB / SQLCipher4 加密格式与密钥模型（参考）

本文件供 `wechat-wcdb-local` 技能使用，记录微信桌面版 4.x 本地数据库的底层格式、密钥派生与已知陷阱。SKILL.md 保持精简，细节统一放这里。

## 1. 总览

微信本地数据库本质是 **SQLCipher 4**。关键常量：

- 页大小 `PAGE_SIZE = 4096`
- 算法：AES-256-CBC + HMAC-SHA512
- KDF 迭代：`256000`（每库 enc_key）、`2`（mac_key）
- HMAC 覆盖长度：`4032` 字节

## 2. 密钥模型（Win / Mac 统一）

1. **passphrase**：32 字节，解密的总密钥。
   - Windows：从微信进程内存的 `Config.Cipher` blob（XOR 掩码解码）定位 `(32B 密钥 + 16B salt)`。
   - macOS：微信启动瞬间 frida 拦截 `CCKeyDerivationPBKDF`，命中 `rounds === 256000 && passwordLen === 32` 的那次调用的第一个参数 (32 字节) 即 passphrase。
   - 通用兜底：用 `--key <hex>` 直接提供。
2. **每库独立 enc_key**：每个 `.db` 首页前 16 字节是该库 salt，
   `enc_key = PBKDF2-HMAC-SHA512(passphrase, db_salt, 256000, 32)`。
   不同库用各自 salt 派生独立密钥。
3. **mac_key**：`mac_salt = db_salt XOR 0x3A`；`mac_key = PBKDF2-HMAC-SHA512(enc_key, mac_salt, 2, 32)`。

## 3. 页面布局

页大小 4096，AES-256-CBC：

- **page 1**：`[0:16] salt | [16:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC-SHA512`
- **page N**：`[0:4016] 密文 | [4016:4032] IV | [4032:4096] HMAC-SHA512`

HMAC 校验范围：

- page 1 覆盖 `[16:4032)`（即密文部分，不含 salt）
- page N 覆盖 `[0:4032)`（整个密文）

IV 取页内 `[4016:4032)`。解密后 page1 前 16 字节还原为 `SQLite format 3\0`。

## 4. 纯 JS 实现要点（src/wcdbDecode.js）

- `computeMacKey(encKeyBuf, salt)`：`xorMaskSalt`（salt XOR 0x3A）后 `PBKDF2-SHA512(iter=2)`。
- `decryptBuffer(encBuf, encKeyHex)`：逐页 HMAC-SHA512 校验 → AES-256-CBC 解密（IV 取页内 `[4016:4032)`）→ page1 前 16 字节还原 magic。
- 错误 enc_key 会触发 HMAC 校验失败（反例已入自测）。
- 纯 JS 实现规避了 `sqlcipher` npm 包依赖 GitHub SSH 源拉取失败的问题，做到 Windows/macOS 零编译一致。

## 5. 消息表与提取（src/extract.js）

- 表名：`Msg_<md5(username)>`（`src/constants.js` 的 `msgTableName`）。
- `local_type`：取低 32 位 `(rawType >>> 0) & 0xffffffff`；高位为子类型标志。例：`244813135921 (0x3900000031) → 49`。
- 内容列：`message_content` / `compress_content` 可能以 zstd magic `28 b5 2f fd` 开头，需解压。
- 群消息：正文以 `wxid_xxx:\n` 前缀标识发送者（`PREFIX_RE = /^([A-Za-z0-9_@-]+):\n/`）。
- `real_sender_id` 反推：每个 `message_N.db` 独立本地索引，库内无映射表；用前缀全表扫描实证构建 `{local_id → wxid}`；无前缀且无映射 = 本人（selfWxid）。
- 列名兼容：`resolveColumns` 兼容 `real_sender_id` / `message_content` / `compress_content` 等不同命名。

## 6. Windows 密钥提取（src/keyExtract.js）

- `Config.Cipher` blob 经固定 XOR 掩码（`WINDOWS_CONFIG_XOR_MASK`）解码。
- 解码后用**步长 1 字节**滑动窗口（误用步长 8 会漏掉未对齐密钥），48 字节窗口取前 32B 为 key、后 16B 为 salt，并 PBKDF2 派生多变体加入候选。
- 实时扫描（best-effort，未真机验证）：`scanProcessMemoryWindows(pid)` 用 koffi 调 `Kernel32` 的 `OpenProcess/VirtualQueryEx/ReadProcessMemory`。
- 兜底：从一个内存 dump 文件 `--dump` 提取，跨平台可测。

## 7. macOS 密钥提取（src/macKeyFrida.js）

- Mac 版微信**无 `Config.Cipher`**（`com.Tencent.WCDB.Config.Cipher` 不存在，只有 `Tokenize / ScalarFunction`），只能用 frida。
- 流程：重签名微信（保留 sandbox）→ root 运行 `key --mac-frida` → 轮询等待微信进程 → `frida.attach` → 加载 hook 脚本（命中 `rounds===256000 && passwordLen===32`）→ 抓到 32 字节 passphrase 写入 `/tmp/wxdb/passphrase.hex` → **必须 `session.detach()`** 避免微信变僵尸进程。
- 必须在微信「启动瞬间」attach，否则启动后不再调用 PBKDF2。

## 8. 已知陷阱

| 项 | 说明 |
|----|------|
| `local_type` 取低 32 位 | 高位是子类型标志，如 `244813135921 (0x3900000031) → 49` |
| zstd 内容 | `message_content` / `compress_content` 可能以 `28 b5 2f fd` 开头，需解压 |
| `real_sender_id` 反推 | 每个 `message_N.db` 独立本地索引，库内无映射表；用「`wxid_xxx:\n` 前缀」全表扫描实证构建 `{local_id → wxid}`；无前缀且无映射 = 本人 |
| Mac 无 `Config.Cipher` | Mac 版只有 frida 路径 |
| salt 附近搜密钥行不通 | 密钥不在 salt ±4KB 内，别在内存里搜 salt 定位密钥 |
| 重签名保留 sandbox | 删掉 `com.apple.security.app-sandbox` 会让微信切到另一数据目录 |
| 表名 bytes 问题 | `Msg_<md5(username)>`；用 better-sqlite3 直读，天然处理字符串列 |

## 9. 验证状态（诚实说明）

**已通过自测（`npm test`，17/17 通过）**：

- zstd 解压往返；`Msg_` 表名 = `Msg_` + md5(username)
- XOR 掩码编解码往返、`collectCandidates` 能回收嵌入的 32B 密钥
- `deriveEncKey`：passphrase + 每库 salt 派生 enc_key，稳定且每库独立
- 纯 JS WCDB 页面解码往返（AES-256-CBC + HMAC-SHA512 + 每页 IV），错误密钥触发 HMAC 校验失败
- 消息提取全流程（合成明文库）：zstd 内容、`local_type` 低 32 位、群前缀解析、`real_sender_id` 反推、「本人」判定

**未经真机验证（本环境无微信安装）**，需真实设备确认：

- 纯 JS 解码对真实微信 4.x `.db` 的解密
- Windows 实时内存扫描（koffi 调用 `OpenProcess/ReadProcessMemory/VirtualQueryEx`）
- macOS frida 抓取 passphrase（依赖重签名微信 + root + 启动时机）
