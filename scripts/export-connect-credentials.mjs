#!/usr/bin/env node
/**
 * export-connect-credentials.mjs —— 五个渠道凭据的**统一导出 / 安装 / 校验**入口。
 *
 * 为什么要有这一个：以前是三个脚本、三种用法，还得记住哪个渠道能自动导、哪个要手填。
 * 现在合成一条命令，并且在末尾统一做一次**只读**校验：
 *
 *   node scripts/export-connect-credentials.mjs            # = all（能自动导的全导 + 校验）
 *   node scripts/export-connect-credentials.mjs workbuddy --account 2
 *   node scripts/export-connect-credentials.mjs trae
 *   node scripts/export-connect-credentials.mjs qoder            # 自动解 App 登录态
 *   node scripts/export-connect-credentials.mjs qoder --pat pt-x # 或直接用官方 PAT
 *   node scripts/export-connect-credentials.mjs verify      # 只校验，不导出
 *   node scripts/export-connect-credentials.mjs bundle      # 打包成 connect-auth.tar.gz（迁移用）
 *   node scripts/export-connect-credentials.mjs restore --bundle <归档>   # 从归档铺回来
 *
 * 各渠道的凭据**只能这样拿到**，没有统一来源：
 *
 * | 渠道 | 来源 | 能不能自动导 |
 * |---|---|---|
 * | WorkBuddy 1/2/3 | 桌面 App 的加密凭据 → 宿主用 App 自带 Electron 解封 | ✅（App 同时只保持一个登录，导谁要先切到谁）|
 * | Trae | `TRAE SOLO CN` 的 byteCrypto 信封，纯 JS 可解 | ✅ |
 * | Qoder CN | **App 的本地登录态**（Electron safeStorage，用钥匙串解；见 qoder-vault.mjs）；官方 PAT 作为兜底 | ✅（读钥匙串时系统可能弹一次授权框）|
 *
 * 落点全部收在 `~/.dsh/connect-auth/`（已 bind mount 进容器 → `/root/.dsh/connect-auth/`），
 * 所以**不用重启容器**；三个渠道的插件各自按 30 秒轮询凭据，最多半分钟生效。
 *
 * 迁移到另一台机器 / 多端部署：只需带走**一个归档** ——
 *   node scripts/export-connect-credentials.mjs bundle
 *   #  把 connect-auth.tar.gz 拷过去
 *   node scripts/export-connect-credentials.mjs restore --bundle connect-auth.tar.gz
 * （`docker-compose.yml` 里三个 `WORKBUDDY{N}_AUTH_FILE` 已默认指向 connect-auth/，无需手改。）
 *
 * 安全约定：本脚本只写统一目录与 `connect-auth.tar.gz`（均 0600，归档里是**明文**），
 *          不改任何其它文件；也**绝不打印** token 内容（只打印长度与有效期）。
 */

import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const project = resolve(here, '..');
const DSH_HOME = process.env.DSH_HOME_DIR ?? join(homedir(), '.dsh');
const CONTAINER = process.env.DSH_CONTAINER ?? 'dsh-harness';
const PORT = process.env.DSH_PORT ?? '3079';

/**
 * **认证的统一落点**（[2026-09-25]）。
 *
 * 五个渠道原先分散在 `~/.dsh/workbuddy/`、`trae/`、`qoder/` 三处，迁移与多端部署要逐个
 * 记路径、极易漏（实测 `devbox/secrets/` 里就缺了企业版那份）。现在全部收进这一个目录，
 * 且插件侧的默认读取路径也已指到这里（trae / qoder 的 provider 默认路径、
 * workbuddy 走 compose 的 `WORKBUDDY{N}_AUTH_FILE`）—— **这个目录就是真源**：
 *
 *   connect-auth/workbuddy1.json       workbuddy 个人账号 1
 *   connect-auth/workbuddy2.json       workbuddy 个人账号 2
 *   connect-auth/workbuddy3.json       workbuddy 企业版
 *   connect-auth/trae.json             Trae
 *   connect-auth/qoder.pat             Qoder 官方 PAT（兜底）
 *   connect-auth/qoder-session.json    Qoder App 会话（优先）
 *
 * 本脚本每次导出后会把结果**同步进来**（见 publishExports），
 * 并提供 `bundle`（收成一个 tar.gz）/ `restore`（从 tar.gz 铺回来）用于迁移。
 */
const AUTH_DIR = join(DSH_HOME, 'connect-auth');
/** 统一目录里的文件名 ← 各渠道自己习惯的旧落点（导出完成后由 publishExports 同步）。 */
const AUTH_FILES = [
  ['workbuddy1.json', join('workbuddy', 'account1.info')],
  ['workbuddy2.json', join('workbuddy', 'account2.info')],
  ['workbuddy3.json', join('workbuddy', 'account3.info')],
  ['trae.json', join('trae', 'credential.json')],
  ['qoder-session.json', join('qoder', 'session.json')],
  ['qoder.pat', join('qoder', 'pat')],
];

// ── 参数 ────────────────────────────────────────────────────────────────────
const argv = process.argv.slice(2);
const command = ['all', 'workbuddy', 'trae', 'qoder', 'verify', 'bundle', 'restore'].includes(argv[0]) ? argv.shift() : 'all';

function flag(name) {
  const index = argv.indexOf(name);
  if (index === -1) return undefined;
  const value = argv[index + 1];
  argv.splice(index, value === undefined || value.startsWith('--') ? 1 : 2);
  return value ?? true;
}

const accountFlag = flag('--account');
const patFlag = flag('--pat');
const bundleFlag = flag('--bundle');
const noVerify = flag('--no-verify') === true;
const dryRun = flag('--dry-run') === true;

if (argv.length > 0) {
  console.error(`无法识别的参数：${argv.join(' ')}`);
  process.exit(2);
}
const account = accountFlag === undefined ? 1 : Number(accountFlag);
if (![1, 2, 3].includes(account)) {
  console.error('--account 只接受 1、2 或 3');
  process.exit(2);
}

const ok = (text) => console.log(`  \x1b[32m✓\x1b[0m ${text}`);
const bad = (text) => console.log(`  \x1b[31m✗\x1b[0m ${text}`);
const info = (text) => console.log(`    ${text}`);
const head = (text) => console.log(`\n\x1b[1m${text}\x1b[0m`);

// ── 子步骤 ──────────────────────────────────────────────────────────────────

/** 跑一个既有导出脚本（保持它们各自经过验证的实现不动）。 */
function runScript(relative, args) {
  const script = join(project, relative);
  if (!existsSync(script)) {
    bad(`找不到 ${relative}`);
    return false;
  }
  if (dryRun) {
    info(`[dry-run] node ${relative} ${args.join(' ')}`);
    return true;
  }
  const result = spawnSync(process.execPath, [script, ...args], { stdio: 'inherit', cwd: project });
  return result.status === 0;
}

function exportWorkbuddy() {
  head(`1) WorkBuddy → connect-auth/workbuddy${account}.json`);
  if (accountFlag === undefined) {
    info('未指定 --account，默认用 1。要导别的账号：先在 App 里切到它，再 --account N。');
  }
  return runScript('scripts/export-wb-plain.mjs', ['--account', String(account)]);
}

function exportTrae() {
  head('2) Trae → connect-auth/trae.json');
  return runScript('scripts/export-trae-plain.mjs', []);
}

/**
 * Qoder 优先用"解 App 本地登录态"这条路 —— 它不需要任何手工步骤。
 *
 * 实测 App 的会话 token（`dt-`）在**两个平面**都是有效 Bearer：OpenAPI（账号/额度/签到）
 * 与推理平面（网关的 COSY 头里带的就是它），所以插件侧走"会话优先"。
 * PAT 作为兜底（PAT 需要用户在网页上自建，且官方明确不自动续期）。
 */
function installQoder() {
  head('3) Qoder CN → connect-auth/qoder-session.json（App 登录态，免 PAT）');
  if (runScript('scripts/qoder-vault.mjs', ['--install-session'])) return true;
  info('App 登录态导出失败（未登录 / 钥匙串未授权 / 格式变了），回落到官方 PAT。');
  return installQoderPat();
}

function installQoderPat() {
  head('3b) Qoder CN → connect-auth/qoder.pat（官方 PAT，兜底）');
  const target = join(AUTH_DIR, 'qoder.pat');
  if (patFlag === undefined) {
    info('未提供 --pat，跳过。');
    info('PAT 只能在 https://qoder.com.cn/account/integrations 自建（pt- 前缀）；');
    info('App 里的 auth.v1.dat 是 Electron safeStorage 加密的，不走那条路。');
    info(`拿到后：node scripts/export-connect-credentials.mjs qoder --pat pt-xxxx`);
    return undefined;
  }
  if (typeof patFlag !== 'string' || !patFlag.trim().startsWith('pt-')) {
    bad('--pat 看起来不是官方 PAT（应以 pt- 开头）');
    return false;
  }
  if (dryRun) {
    info(`[dry-run] 写入 ${target}（0600，${patFlag.trim().length} 字符）`);
    return true;
  }
  try {
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, `${patFlag.trim()}\n`, { mode: 0o600 });
    try {
      chmodSync(target, 0o600);
    } catch {
      /* 已存在时可能改不动权限，不致命 */
    }
  } catch (error) {
    bad(`写入失败：${error.message}`);
    return false;
  }
  ok(`已写入 ${target}（0600，${patFlag.trim().length} 字符，不打印内容）`);
  return true;
}

/**
 * 把各渠道刚导出的凭据**同步进统一目录**。
 *
 * 为什么需要这一步：三个导出的子脚本各自写自己习惯的落点（`workbuddy/accountN.info`、
 * `trae/credential.json`、`qoder/session.json`），而插件现在读的是 `connect-auth/`。
 * 与其改三个子脚本（它们也能独立使用），不如在这里做一次搬运 —— 导出即生效。
 *
 * 只复制存在的源；0600；不打印内容。
 */
function publishExports() {
  head('3c) 同步进统一目录 connect-auth/');
  if (dryRun) {
    info(`[dry-run] 把导出的文件复制进 ${AUTH_DIR}`);
    return true;
  }
  let copied = 0;
  try {
    mkdirSync(AUTH_DIR, { recursive: true, mode: 0o700 });
  } catch (error) {
    bad(`建目录失败：${error.message}`);
    return false;
  }
  for (const [name, legacy] of AUTH_FILES) {
    const from = join(DSH_HOME, legacy);
    const to = join(AUTH_DIR, name);
    if (!existsSync(from)) continue;
    try {
      copyFileSync(from, to);
      chmodSync(to, 0o600);
      copied += 1;
      ok(`${name}  ←  ${legacy}`);
    } catch (error) {
      bad(`${name} 同步失败：${error.message}`);
    }
  }
  if (copied === 0) info('（没有可同步的源文件）');
  return true;
}

/** 统一目录里当前有哪些渠道（用于 bundle / 状态展示）。 */
function authDirState() {
  if (!existsSync(AUTH_DIR)) return [];
  return AUTH_FILES.map(([name]) => name).filter((name) => existsSync(join(AUTH_DIR, name)));
}

/**
 * 打包统一目录 → 一个 tar.gz。迁移/多端部署只需要带走这一个文件。
 *
 * 刻意**不用** tar 的绝对路径（否则解包时会覆盖到原机的绝对路径），
 * 用 `-C <dir> .` 让归档里只有相对文件名。
 */
function bundleAuthDir() {
  head('bundle) 打包 connect-auth → 单个归档');
  const names = authDirState();
  if (names.length === 0) {
    bad(`统一目录里还没有任何凭据：${AUTH_DIR}`);
    return false;
  }
  const out = typeof bundleFlag === 'string' ? bundleFlag : join(project, 'connect-auth.tar.gz');
  if (dryRun) {
    info(`[dry-run] tar -czf ${out} -C ${AUTH_DIR} .`);
    return true;
  }
  const result = spawnSync('tar', ['-czf', out, '-C', AUTH_DIR, '.'], { encoding: 'utf8' });
  if (result.status !== 0) {
    bad(`打包失败：${result.stderr ?? result.status}`);
    return false;
  }
  ok(`已写出 ${out}`);
  info(`包含 ${names.length} 个文件：${names.join(', ')}`);
  info('⚠️ 归档里是**明文**凭据，请当作密钥保管（别提交进 git）。');
  return true;
}

/** 从归档铺回统一目录。 */
function restoreAuthDir() {
  head('restore) 从归档铺回 connect-auth');
  const from = typeof bundleFlag === 'string' ? bundleFlag : join(project, 'connect-auth.tar.gz');
  if (!existsSync(from)) {
    bad(`找不到归档：${from}`);
    info('用法：--bundle <路径>，或把归档放在仓库根目录的 connect-auth.tar.gz。');
    return false;
  }
  if (dryRun) {
    info(`[dry-run] tar -xzf ${from} -C ${AUTH_DIR}`);
    return true;
  }
  mkdirSync(AUTH_DIR, { recursive: true, mode: 0o700 });
  const result = spawnSync('tar', ['-xzf', from, '-C', AUTH_DIR], { encoding: 'utf8' });
  if (result.status !== 0) {
    bad(`解包失败：${result.stderr ?? result.status}`);
    return false;
  }
  for (const name of authDirState()) {
    try {
      chmodSync(join(AUTH_DIR, name), 0o600);
    } catch {
      /* 不致命 */
    }
  }
  const names = authDirState();
  ok(`已铺回 ${names.length} 个文件：${names.join(', ')}`);
  info('新机器上还需要：把 docker-compose.yml 的 WORKBUDDY{N}_AUTH_FILE 指到 connect-auth/（已默认指向）。');
  return true;
}

/** 只读校验：读面板的聚合状态（它自己会扇出到五个渠道）。 */
function verifyChannels() {
  head('4) 只读校验（面板聚合视图）');
  if (dryRun) {
    info('[dry-run] docker exec … curl /plugins/dsh-connect/status');
    return true;
  }
  const response = spawnSync(
    'docker',
    ['exec', CONTAINER, 'curl', '-s', '--max-time', '60', `http://127.0.0.1:${PORT}/plugins/dsh-connect/status`],
    { encoding: 'utf8', maxBuffer: 1 << 24 },
  );
  if (response.status !== 0 || !response.stdout) {
    bad(`读不到面板状态（docker exec 失败或容器不在跑）。容器：${CONTAINER}`);
    info('也可以直接看 UI 的「认证」区。');
    return false;
  }
  let doc;
  try {
    doc = JSON.parse(response.stdout);
  } catch {
    bad('面板返回的不是 JSON');
    return false;
  }
  let signedIn = 0;
  for (const channel of doc.channels ?? []) {
    const credits = channel.credits === undefined ? '—' : channel.credits.label ?? '—';
    const line = `${channel.displayName}（${channel.id}）：${channel.state} · 额度 ${credits}`;
    if (channel.state === 'signed-in') {
      signedIn += 1;
      ok(line);
    } else if (channel.state === 'signed-out') {
      bad(`${line}${channel.error === undefined ? '' : ` — ${channel.error}`}`);
    } else {
      bad(line);
    }
  }
  info(`已登录 ${signedIn} / ${(doc.channels ?? []).length}`);
  return true;
}

// ── 主流程 ──────────────────────────────────────────────────────────────────
console.log(`dsh-connect 凭据工具 · 命令=${command} · 账号=${account} · 容器=${CONTAINER}`);
console.log(`统一落点：${AUTH_DIR}（随 ~/.dsh 挂进容器 → /root/.dsh/connect-auth）`);

// 打包 / 恢复与导出无关，各走一条短路。
if (command === 'bundle') process.exit(bundleAuthDir() ? 0 : 1);
if (command === 'restore') process.exit(restoreAuthDir() ? 0 : 1);

let failed = false;
if (command === 'all' || command === 'workbuddy') {
  if (!exportWorkbuddy()) failed = true;
}
if (command === 'all' || command === 'trae') {
  if (!exportTrae()) failed = true;
}
if (command === 'all' || command === 'qoder') {
  if (installQoder() === false) failed = true;
}
// 导出完立刻同步进统一目录 —— 插件读的是那里，不同步等于白导。
if (command !== 'verify') {
  if (!publishExports()) failed = true;
}

const shouldVerify = command !== 'verify' ? !noVerify : true;
if (shouldVerify) {
  if (!verifyChannels()) failed = true;
}

head('小结');
info('插件按 30 秒轮询凭据，改动最多半分钟生效（不用重启容器）。');
info('WorkBuddy 切换账号：在 App 里切到目标账号 → 再跑 `--account N`。');
info('Qoder 的 PAT 不会自动续期（官方文档明确）；过期就换新的。');
process.exit(failed ? 1 : 0);
