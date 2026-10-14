# 修复方案（配套 docs/code-review.md）

按 code-review.md 的优先级给出的落地补丁清单。每条标注影响文件与回归验证方式。

> **行号说明**：已按提交 `3ec089a`（报告多格式模板，重排了 `bin/wcdb.js` 的 action 结构）复核并更新；`src/keyExtract.js` / `src/decrypt.js` / `src/wcdbDecode.js` / `src/extract.js` 未被该提交触及，行号不变。
>
> **本会话已修复、尚未提交（`src/macKeyFrida.js`）**：真实 macOS 首跑 `--mac-frida` 失败复盘后新增的两项 —— ① `diagnoseAttachFailure()`：把 frida 的 `Unable to access process with pid N from the current user account` 转成「是否 root / SIP 状态 / 目标有无 `get-task-allow` / 命中的是不是未重签名副本」的可操作提示；② `listWeChatMainProcesses()`：按主二进制完整路径精确匹配，取代会命中 10 个微信相关进程的 `pgrep -f` 特征串。复盘见 code-review.md 附录 B。

---

## 第一批：恢复主路径可用性（C-1、M-1）

### 1.1 候选生成去掉重 KDF，改为「采集 + 延后验证」

`src/keyExtract.js`

- 新增 `collectKeySaltPairs(decoded)`：只做 O(1) 采集 `{key32, salt16}`，带 `MAX_CANDIDATES`（建议 20000）硬上限，**不再** 调用 `crypto.pbkdf2Sync`。
- `collectCandidates` 保留为薄封装（对 raw32 去重后返回），`PBKDF2_VARIANTS` 的派生移到「验证阶段」按**该库首页 salt** 派生，与 `src/decrypt.js:63-66` 口径统一。
- `extractKeysFromDump` / `scanProcessMemoryWindows`（`src/keyExtract.js:82-86`、`:179`）改为消费 pairs，并加进度输出（每处理 8MB 打一行），让 agent 可区分「在跑」与「挂死」。

验证：新增断言「256KB 输入耗时 < 500ms 且候选数 ≤ 20000」；`node test/selftest.js` 现有 `[keyExtract]` 两条断言须仍通过。

### 1.2 解密改流式，取消整库驻留

`src/wcdbDecode.js` + `src/decrypt.js`

- `decryptBuffer(encBuf, encKeyHex)` → 新增 `decryptToStream(encFd, encKeyHex, outFd)`：每次读 4096 页 → HMAC 校验 → AES-CBC 解密 → 写 4096 输出；输出页末 80 字节补零（保持现有 reserved 语义，见 `src/wcdbDecode.js:16-18`）。
- `src/decrypt.js:135` 的 `fs.readFileSync(encPath)` 换成「只读首页拿 salt」+ 流式句柄；保留 `decryptBuffer` 给自测使用。

验证：现有 `[wcdbDecode]` 往返与「错误密钥触发 HMAC 失败」两条断言须仍通过；补一条「大文件解密期间 RSS 峰值 < 文件大小」。

---

## 第二批：堵住密钥暴露面（C-2、M-5、C-3）

### 2.1 密钥文件 0600 + 移出共享 tmp

- `src/macKeyFrida.js:11`：`DEFAULT_PASSPHRASE_PATH` 由 `os.tmpdir()/wxdb/passphrase.hex` 改为 `os.homedir()` 下的私有目录（如 `.wcdb-local/`）。
- `src/macKeyFrida.js:233-234`：`mkdirSync(dir, { recursive: true, mode: 0o700 })` + `writeFileSync(out, data, { encoding: 'utf8', mode: 0o600 })` + `chmodSync(out, 0o600)`（Windows 下 try/catch 忽略）。
- `bin/wcdb.js:57`、`bin/wcdb.js:68`：写 `keys.json` 同样加 `{ mode: 0o600 }`。
- `src/macKeyFrida.js:230`：异常信息不再拼接 `captured` 原文，只输出长度与前 8 位。

验证：`fs.statSync(out).mode & 0o777 === 0o600` 断言。

### 2.2 stdout 不输出密钥原文

`bin/wcdb.js:71-74`：`console.log('首个候选（供快速试解密）：', cands[0])` → 指纹形式：

```js
console.log(`首个候选指纹：${cands[0].slice(0, 8)}…（完整值见 ${opts.out}，请视为机密文件）`);
```

### 2.3 `decrypt` 子命令补 await

`bin/wcdb.js:86`（action 改 `async`）、`bin/wcdb.js:93`（加 `await`）。这让 `bin/wcdb.js:244-249` 的统一「错误：<可操作提示> + exit 1」重新生效。

同时 `bin/wcdb.js:106-108`（`extract`）的 `db.close()` 移入 `finally`，与 `src/pipeline.js:133-138` 对齐。

验证：新增 CLI smoke test —— 用合成小库 + 错误密钥跑 `node bin/wcdb.js decrypt`，断言 stderr 以 `错误：` 开头、退出码为 1、且不出现堆栈。

---

## 第三批：错误归因与资源释放（M-3、M-6、M-4、M-2）

### 3.1 后端探测移出候选循环

`src/decrypt.js:131-166`：先一次性判断 sqlcipher 是否可用（默认安装下不可用，见 code-review 附录），循环内只走 JS 路径；失败信息分开汇总 `jsFirstError` 与 `sqlcipherFirstError`，避免把「passphrase 不对」报成「缺原生模块」。顺带清理 `src/decrypt.js:161` 的无效 `.catch(() => {})`（`closeDb` 永不 reject）与 `src/decrypt.js:157`/`:161` 的双重 close。

### 3.2 frida 定时器与 promise

`src/macKeyFrida.js:196-226`：保存 `timer` 并在 `finally` 中 `clearTimeout(timer)`；`done` 改标准 `{resolve, reject}`，去掉 `r instanceof Error` 判定；`finally` 内补 `await script.unload()`。

验证：成功抓取后进程应立即退出（当前最多多活 90 秒）。

### 3.3 消息表单次遍历

`src/extract.js:75-145`：`buildSenderMap` 与消息提取合并为一次 `stmt.iterate()` 遍历，前缀命中行同时写 senderMap 与结果数组，最后按 `create_time` 排序输出。`src/zstd.js:13-29` 的 `_loading` 失败时置空。

### 3.4 路径参数化

`src/decrypt.js:117`：`ATTACH DATABASE ? AS plain KEY ''` + 绑定参数（或 `outPath.replace(/'/g, "''")`）。
`src/decrypt.js:180-183`：`--files` 条目先 `path.basename` 再用 target 白名单校验，禁止越出 `--dir`。

---

## 第四批：规范清理（m-2 … m-10）

低改动量，可在同一次提交内带走：`bin/wcdb.js:5` 删除未用的 `path`；`src/extract.js:59/63` 去重兼容列名；`src/extract.js:130` 去掉恒等掩码并兼容 BigInt；`src/extract.js:139` 秒/毫秒按位数判定；`src/extract.js:152-169` 加 `finally` 与一行 warn；`src/platform.js:83` 包 try/catch；`src/macKeyFrida.js:129` 兼容 `Module.findExportByName(null, name)` 并把 `frida` 加进 optionalDependencies；`src/decrypt.js:19` 与 `src/keyExtract.js:13-18` 的版本参数合并到 `src/constants.js`。

---

## 建议的提交切分

1. `fix: decrypt 子命令 await + extract close finally + 移除密钥原文输出` —— 最小、最安全，先落地。
2. `security: passphrase/keys 落盘 0600 且默认路径移出共享 tmp`
3. `perf: 候选生成去 KDF（带数量上限）+ 解密改流式` —— 改动最大，需要新增两条断言守住。
4. `fix: 解密失败原因归因 + frida 定时器清理 + 消息表单次遍历 + ATTACH 参数化`
5. `chore: 规范清理`

每批之后跑 `node test/selftest.js`，并补 code-review「测试覆盖缺口」中列出的 4 类断言。
