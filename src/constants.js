'use strict';

const crypto = require('crypto');

/**
 * WCDB 4.1+ Windows Config.Cipher XOR 掩码（来源：freestylefly/wcdb-key-tool）。
 * 微信进程内存中 Config.Cipher 的二进制配置块用该掩码按字节 XOR 编码，
 * 解码后可在其中定位 (32B 派生密钥 / passphrase + 16B salt) 对。
 */
const WINDOWS_CONFIG_XOR_MASK = Buffer.from(
  'd2c7442458020000004889442450488b450048844c2448488944254048584c24',
  'hex'
);

/**
 * zstd 压缩 magic（小端读取为 0xFD2FB528，字节序为 28 B5 2F FD）。
 * message_content / compress_content 若以此 4 字节开头即为 zstd 压缩。
 */
const ZSTD_MAGIC = Buffer.from([0x28, 0xb5, 0x2f, 0xfd]);

/**
 * 消息表名：Msg_ + md5(username) 小写十六进制。
 * @param {string} username wxid / 群 id
 * @returns {string}
 */
function msgTableName(username) {
  return 'Msg_' + crypto.createHash('md5').update(String(username), 'utf8').digest('hex');
}

module.exports = {
  WINDOWS_CONFIG_XOR_MASK,
  ZSTD_MAGIC,
  msgTableName
};
