#!/usr/bin/env node
/**
 * qoder-vault.mjs —— 解开 Qoder CN 桌面 App 的本地登录态（`auth.v1.dat`）。
 *
 * ## 它是什么
 *
 * Qoder CN（`com.qodercn.app`）用 Electron 的 `safeStorage.encryptString()` 把登录态写到
 *
 *   ~/Library/Application Support/com.qodercn.app.stable/auth.v1.dat
 *
 * 那是 Chromium 的 OSCrypt 格式：`"v10"` + 16 字节 IV + AES-128-CBC 密文；
 * 密钥不在文件里，而在**钥匙串**：
 *
 *   service = "Qoder CN App Safe Storage", account = "Qoder CN App Key"
 *
 * 派生方式：`PBKDF2-SHA1(password=<钥匙串里的那串字符>, salt="saltysalt", iterations=1003, keylen=16)`。
 * 注意 password 用的是钥匙串返回的**原始字符串**（形如 `djMk...DA==`），不是它的 base64 解码。
 *
 * ## 为什么可以做
 *
 * 解开只读，不改任何文件；也不需要 App 的私有 binding（与 WorkBuddy 那条路不同 ——
 * 那条必须跑 App 自带 Electron 的私有 binding，这条纯 Node 就能算）。
 * 代价：读钥匙串时 macOS 可能弹一次授权框（这是系统行为，不是脚本在提权）。
 *
 * ## 用法
 *
 *   node scripts/qoder-vault.mjs --check          # 只解，打印结构（脱敏），不写任何文件
 *   node scripts/qoder-vault.mjs --dump           # 解出完整明文到 stdout（含密钥，慎用）
 *   node scripts/qoder-vault.mjs --install-session # ★ 把 App 登录态装成 ~/.dsh/qoder/session.json
 *   node scripts/qoder-vault.mjs --probe           # 只读探测：这个 token 能不能当 Bearer 打 OpenAPI
 *
 * ## 装出来的东西能直接用吗
 *
 * **能。** 实测 App 的会话 token（`dt-`）在 Qoder 的**两个平面**都是有效 Bearer：
 * OpenAPI（userinfo / 额度 / 签到 全部 200）与推理平面（网关的 COSY 头里带的就是它）。
 * 所以插件侧新增了"会话优先"的凭据源：导出了 session.json 就不需要官方 PAT
 * （PAT 仍是兜底；两者都不需要手工逆向，只是一个自动一个要网页自建）。
 *
 * 退出码：0 成功；2 拿不到钥匙串密钥（未授权/无条目）；3 解不开（格式或密钥不符）。
 */

import { createDecipheriv, pbkdf2Sync } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';

const AUTH_FILE = process.env.QODER_AUTH_FILE
  ?? join(homedir(), 'Library/Application Support/com.qodercn.app.stable/auth.v1.dat');
const KEYCHAIN_SERVICE = process.env.QODER_KEYCHAIN_SERVICE ?? 'Qoder CN App Safe Storage';
const KEYCHAIN_ACCOUNT = process.env.QODER_KEYCHAIN_ACCOUNT ?? 'Qoder CN App Key';
const PAT_TARGET = join(process.env.DSH_HOME_DIR ?? join(homedir(), '.dsh'), 'qoder', 'pat');

const args = new Set(process.argv.slice(2));
const ok = (t) => console.log(`  \x1b[32m✓\x1b[0m ${t}`);
const bad = (t) => console.log(`  \x1b[31m✗\x1b[0m ${t}`);
const info = (t) => console.log(`    ${t}`);

// ── 1. 取钥匙串密钥 ─────────────────────────────────────────────────────────
function keychainPassword() {
  const result = spawnSync('security', ['find-generic-password', '-s', KEYCHAIN_SERVICE, '-a', KEYCHAIN_ACCOUNT, '-w'], {
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    return { error: (result.stderr || '').trim() || `security 退出码 ${result.status}` };
  }
  const value = (result.stdout || '').trim();
  if (value === '') return { error: '钥匙串返回了空密码' };
  return { password: value };
}

// ── 2. OSCrypt 解密 ────────────────────────────────────────────────────────
/**
 * Chromium OSCrypt（macOS）：PBKDF2-SHA1(password, "saltysalt", 1003, 16) 作 AES-128-CBC 密钥。
 *
 * 这里**多试两种 password 形态**：历史版本/不同 Electron 分支里，password 可能是
 * 钥匙串原始字符串，也可能是它的 base64 解码再按 latin1 解释的字节。哪种能通过
 * PKCS7 padding 校验，就是它（padding 校验是很强的判据，错密钥几乎不可能通过）。
 */
function deriveKeys(password) {
  const salt = Buffer.from('saltysalt', 'utf8');
  const variants = [{ label: '原始字符串', password: Buffer.from(password, 'utf8') }];
  try {
    const decoded = Buffer.from(password, 'base64');
    if (decoded.length > 0) variants.push({ label: 'base64 解码后按 latin1', password: Buffer.from(decoded.toString('latin1'), 'utf8') });
  } catch {
    /* 不是 base64 就算了 */
  }
  variants.push({ label: '空密码（旧版回退）', password: Buffer.from('', 'utf8') });
  return variants.map((variant) => ({
    label: variant.label,
    key: pbkdf2Sync(variant.password, salt, 1003, 16, 'sha1'),
  }));
}

function openDocument(raw) {
  if (raw.subarray(0, 3).toString('ascii') !== 'v10' && raw.subarray(0, 3).toString('ascii') !== 'v11') {
    // 没前缀就直接当密文试（Electron safeStorage 在部分平台上不加前缀）
    return { prefix: '(无前缀)', iv: raw.subarray(0, 16), ciphertext: raw.subarray(16) };
  }
  return { prefix: raw.subarray(0, 3).toString('ascii'), iv: raw.subarray(3, 19), ciphertext: raw.subarray(19) };
}

function tryDecrypt(key, iv, ciphertext) {
  try {
    const decipher = createDecipheriv('aes-128-cbc', key, iv);
    const plain = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return { plain };
  } catch (error) {
    return { error: error.message };
  }
}

// ── 主流程 ──────────────────────────────────────────────────────────────────
console.log(`输入：${AUTH_FILE}`);
if (!existsSync(AUTH_FILE)) {
  bad('文件不存在 —— 先在 Qoder CN App 里登录一次');
  process.exit(2);
}

const raw = readFileSync(AUTH_FILE);
const opened = openDocument(raw);
console.log(`格式：前缀=${opened.prefix} IV=${opened.iv.length}B 密文=${opened.ciphertext.length}B`);

const keyResult = keychainPassword();
if (keyResult.error !== undefined) {
  bad(`读钥匙串失败：${keyResult.error}`);
  info('常见原因：系统弹了授权框但被拒绝，或在无 GUI 的会话里跑。');
  info('重试：在桌面上执行，并在弹框里点「始终允许」。');
  process.exit(2);
}
ok(`钥匙串密钥已取到（${keyResult.password.length} 字符，不打印内容）`);

let plain;
let usedLabel;
for (const candidate of deriveKeys(keyResult.password)) {
  const attempt = tryDecrypt(candidate.key, opened.iv, opened.ciphertext);
  if (attempt.plain !== undefined) {
    plain = attempt.plain;
    usedLabel = candidate.label;
    break;
  }
}
if (plain === undefined) {
  bad('三种 password 形态都解不开（padding 校验失败）');
  process.exit(3);
}
ok(`已解密（password 形态：${usedLabel}）→ ${plain.length} 字节`);

let document;
let asJson = true;
const plainText = plain.toString('utf8');
try {
  document = JSON.parse(plainText);
} catch {
  // 实测：App 写出的这份 JSON **缺了开头 5 个字节**（恒为 `{"v"`，即文件里以 `:1,` 开头）。
  // 补回后才能解析 —— 只在"补上后确实拿到预期键"时才认，这样格式一变就会退化成
  // "解不开"而不是悄悄给出半成品。
  try {
    const repaired = JSON.parse('{"v"' + plainText);
    if (repaired !== null && typeof repaired === 'object' && typeof repaired.token === 'string') {
      document = repaired;
    } else {
      asJson = false;
    }
  } catch {
    asJson = false;
  }
}

if (args.has('--dump')) {
  process.stdout.write(plain.toString('utf8'));
  process.stdout.write('\n');
  process.exit(0);
}

// 默认只打结构（脱敏）：键名 + 值的长度，不含内容
console.log('\n解密结果结构（脱敏）：');
if (!asJson) {
  info(`不是 JSON（前 80 字节按 latin1）：${plain.subarray(0, 80).toString('latin1').replace(/[^\x20-\x7e]/g, '·')}`);
} else {
  const shape = (node, depth = 0) => {
    if (depth > 4) return '…';
    if (Array.isArray(node)) return node.slice(0, 3).map((item) => shape(item, depth + 1));
    if (node !== null && typeof node === 'object') {
      const out = {};
      for (const [key, value] of Object.entries(node)) out[key] = shape(value, depth + 1);
      return out;
    }
    if (typeof node === 'string') {
      // 只保留"能看出是什么"的前缀，其余用长度代替 —— 避免把 token 整串打出来
      const head = node.length > 12 ? node.slice(0, 12).replace(/[A-Za-z0-9+/=_-]{6,}/g, '<redacted>') : node;
      return `<str ${node.length}${node.startsWith('pt-') ? ' pt-*' : ''}${node.length > 12 ? ` head=${head}…` : ''}>`;
    }
    return node;
  };
  console.log(JSON.stringify(shape(document), null, 1));
}

// ── --probe：这个会话 token 能不能直接当 Bearer 用（只读）──────────────────
if (args.has('--probe')) {
  const token = asJson && typeof document.token === 'string' ? document.token.trim() : '';
  const uid = asJson && typeof document.id === 'string' ? document.id.trim() : '';
  console.log(`\n会话 token：${token === '' ? '(没找到)' : `${token.slice(0, 3)}…（${token.length} 字符）`}`);
  if (token === '') process.exit(3);

  const headers = {
    accept: 'application/json',
    authorization: `Bearer ${token}`,
    'cosy-clienttype': '5',
    'user-agent': 'Qoder',
  };
  const probes = [
    ['userinfo', 'https://openapi.qoder.com.cn/api/v1/userinfo'],
    ['额度 /sash/api/v2/me/usage', 'https://openapi.qoder.com.cn/sash/api/v2/me/usage'],
    ['签到 /sash/api/v1/me/campaigns', 'https://openapi.qoder.com.cn/sash/api/v1/me/campaigns'],
  ];
  for (const [label, url] of probes) {
    try {
      const response = await fetch(url, { headers, signal: AbortSignal.timeout(20000) });
      const text = await response.text();
      let shape = text.slice(0, 160).replace(/\s+/g, ' ');
      try {
        const doc = JSON.parse(text);
        shape = doc === null ? 'null' : `keys=${Object.keys(doc).slice(0, 8).join(',')}`;
      } catch {
        /* 不是 JSON 就原样截断 */
      }
      const line = `${label} → HTTP ${response.status}  ${shape}`;
      if (response.ok) ok(line);
      else bad(line);
    } catch (error) {
      bad(`${label} → ${error.message}`);
    }
  }
  console.log(`\nuid（COSY 签名需要）：${uid === '' ? '(没找到)' : `${uid.slice(0, 8)}…`}`);
  info('上面若都是 200，说明 App 的会话 token 可以直接打 OpenAPI 平面（额度/签到）。');
  info('推理平面（模型目录/对话）走 COSY 签名，需要再用插件自己的实现验证。');
  process.exit(0);
}

// ── --install-session：把 App 登录态装成插件认识的会话文件 ──────────────────
if (args.has('--install-session')) {
  const sessionTarget = join(process.env.DSH_HOME_DIR ?? join(homedir(), '.dsh'), 'qoder', 'session.json');
  if (!asJson || typeof document.token !== 'string' || document.token.trim() === '') {
    bad('解出来的内容里没有可用的 token，装不了');
    process.exit(3);
  }
  const uid = typeof document.user?.id === 'string' ? document.user.id : typeof document.id === 'string' ? document.id : '';
  if (uid === '') {
    bad('解出来的内容里没有 uid（COSY 签名需要），装不了');
    process.exit(3);
  }
  const payload = {
    token: document.token.trim(),
    refreshToken: typeof document.refreshToken === 'string' ? document.refreshToken : '',
    expiresAt: typeof document.expiresAt === 'string' ? document.expiresAt : '',
    uid,
    name: typeof document.user?.name === 'string' ? document.user.name : '',
    email: typeof document.user?.email === 'string' ? document.user.email : '',
  };
  try {
    mkdirSync(dirname(sessionTarget), { recursive: true });
    writeFileSync(sessionTarget, `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
    try {
      chmodSync(sessionTarget, 0o600);
    } catch {
      /* 已有文件时可能改不动权限 */
    }
  } catch (error) {
    bad(`写入失败：${error.message}`);
    process.exit(1);
  }
  ok(`已安装会话凭据 → ${sessionTarget}（0600）`);
  info(`token=${payload.token.slice(0, 3)}…（${payload.token.length} 字符，不打印内容）  uid=${uid.slice(0, 8)}…`);
  info(`过期时间：${payload.expiresAt === '' ? '(未知)' : payload.expiresAt}`);
  info('插件按 30 秒轮询凭据，最多半分钟生效（不用重启容器）。');
  info('App 会自己续期；过期后重跑本命令即可。');
  process.exit(0);
}

// 找一个可用的 PAT（pt- 开头）
function findPat(node, path = '$', out = []) {
  if (typeof node === 'string') {
    if (node.trim().startsWith('pt-') && node.trim().length > 10) out.push({ path, value: node.trim() });
    return out;
  }
  if (Array.isArray(node)) {
    node.forEach((item, index) => findPat(item, `${path}[${index}]`, out));
    return out;
  }
  if (node !== null && typeof node === 'object') {
    for (const [key, value] of Object.entries(node)) findPat(value, `${path}.${key}`, out);
  }
  return out;
}

const pats = asJson ? findPat(document) : [];
console.log('\n结论：');
if (pats.length > 0) {
  ok(`找到 ${pats.length} 个 pt- 开头的 PAT：${pats.map((p) => p.path).join('、')}`);
  if (args.has('--install-pat')) {
    try {
      mkdirSync(dirname(PAT_TARGET), { recursive: true });
      writeFileSync(PAT_TARGET, `${pats[0].value}\n`, { mode: 0o600 });
      try {
        chmodSync(PAT_TARGET, 0o600);
      } catch {
        /* 已有文件时可能改不动权限 */
      }
      ok(`已安装到 ${PAT_TARGET}（0600，不打印内容）`);
      info('插件按 30 秒轮询凭据，最多半分钟生效。');
    } catch (error) {
      bad(`写入失败：${error.message}`);
      process.exit(1);
    }
  } else {
    info('加 --install-pat 可把它装到 ~/.dsh/qoder/pat');
  }
} else {
  info('解密出的内容里**没有 pt- 开头的 PAT** —— 里面是 App 自己的会话凭据（推理平面用 COSY 签名），');
  info('而插件走的是官方 PAT → jobToken 那条 OpenAPI 平面，两者不通用。');
  info('PAT 仍需在 https://qoder.com.cn/account/integrations 自建，然后：');
  info('  node scripts/export-connect-credentials.mjs qoder --pat pt-xxxx');
}
