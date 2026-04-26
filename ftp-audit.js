#!/usr/bin/env node
/**
 * ftp-audit.js
 * READ-ONLY audit of a website served from shared hosting.
 * Supports three protocols:
 *   - SFTP (FTP over SSH, port 22)            <- recommended, encrypted
 *   - FTPS (FTP over TLS, port 21 or 990)     <- encrypted
 *   - plain FTP (port 21)                     <- cleartext creds, avoid
 *
 * Detects common SEO injection / pharma hack / japanese keyword hack
 * vectors and PHP backdoors. Read-only: NO downloads to local disk,
 * NO writes to the server.
 *
 * Usage:
 *   1. Copy .env.example to .env and fill in credentials
 *   2. npm install
 *   3. node ftp-audit.js
 *
 * License: MIT.
 */

require('dotenv').config();
const { Writable } = require('stream');

// Resolve the protocol. FTP_PROTOCOL wins over FTP_SECURE (legacy).
function resolveProtocol() {
  const explicit = (process.env.FTP_PROTOCOL || '').toLowerCase().trim();
  if (['sftp', 'ftps', 'ftp'].includes(explicit)) return explicit;
  // Backwards-compat: FTP_SECURE=true means FTPS
  if ((process.env.FTP_SECURE || '').toLowerCase() === 'true') return 'ftps';
  return 'sftp'; // safe default
}

const PROTOCOL = resolveProtocol();
const DEFAULT_PORT = PROTOCOL === 'sftp' ? 22 : 21;

const C = {
  protocol: PROTOCOL,
  host: process.env.FTP_HOST,
  user: process.env.FTP_USER,
  pass: process.env.FTP_PASS,
  path: process.env.FTP_PATH || '/public_html',
  port: parseInt(process.env.FTP_PORT || DEFAULT_PORT, 10),
};

if (!C.host || !C.user || !C.pass) {
  console.error('ERROR: missing FTP_HOST / FTP_USER / FTP_PASS in .env');
  console.error('Copy .env.example to .env and fill in the values.');
  process.exit(1);
}

// Whitelist of files and folders expected in the site root.
const EXPECTED_ROOT = new Set((process.env.EXPECTED_ROOT || [
  'index.html', 'index.php',
  'robots.txt', 'sitemap.xml', 'favicon.ico', '.htaccess',
  'css', 'js', 'img', 'images', 'assets', 'fonts',
].join(',')).split(',').map(s => s.trim()).filter(Boolean));

// Suspicious filename patterns
const SUSPICIOUS_NAMES = [
  /pgsoft/i, /casino/i, /aposta/i, /jogo/i, /slot/i, /bingo/i, /poker/i,
  /viagra/i, /pharma/i, /pillen/i, /cialis/i, /levitra/i,
  /shell\.php/i, /c99\.php/i, /r57\.php/i, /webshell/i, /backdoor/i,
  /\.suspected$/i, /\.bak$/i, /\.old$/i, /\.orig$/i, /~$/,
  /^wp-/i, /wordpress/i,
];

// Hack patterns in PHP content (matched after downloading each .php file)
const PHP_HACK_PATTERNS = [
  { re: /eval\s*\(\s*base64_decode/i, msg: 'eval(base64_decode) - classic backdoor' },
  { re: /eval\s*\(\s*gzinflate/i, msg: 'eval(gzinflate) - obfuscation' },
  { re: /eval\s*\(\s*str_rot13/i, msg: 'eval(str_rot13) - obfuscation' },
  { re: /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i, msg: 'assert() over input' },
  { re: /\$_(POST|GET|REQUEST)\[[^\]]+\]\s*\(/i, msg: 'callable from HTTP input' },
  { re: /preg_replace\s*\([^,]+\/e[^,]*,/i, msg: 'preg_replace with /e modifier (eval)' },
  { re: /system\s*\(\s*\$_/i, msg: 'system() over input' },
  { re: /shell_exec\s*\(\s*\$_/i, msg: 'shell_exec() over input' },
  { re: /passthru\s*\(\s*\$_/i, msg: 'passthru() over input' },
  { re: /file_put_contents\s*\([^,]+,\s*\$_/i, msg: 'file_put_contents with unsanitized input' },
  { re: /move_uploaded_file/i, msg: 'upload handler (review context)' },
  { re: /mail\s*\(\s*\$_(POST|GET|REQUEST)/i, msg: 'mail() with destination from input (open relay)' },
  { re: /\$[a-zA-Z_]+\s*=\s*["'][a-zA-Z0-9+/=]{500,}["']/i, msg: 'long base64-like string (likely obfuscated payload)' },
  { re: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, msg: 'hex-encoded payload' },
];

// =========================================================================
// Per-protocol adapters. Single interface so walk + analysis stay constant.
// =========================================================================

class BufferStream extends Writable {
  constructor() { super(); this.chunks = []; }
  _write(chunk, _, cb) { this.chunks.push(chunk); cb(); }
  get data() { return Buffer.concat(this.chunks); }
}

class BasicFtpAdapter {
  // Plain FTP and FTPS via the basic-ftp library.
  constructor(config) {
    this.config = config;
    const ftp = require('basic-ftp');
    this.client = new ftp.Client(20000);
    this.client.ftp.verbose = false;
  }
  async connect() {
    await this.client.access({
      host: this.config.host,
      port: this.config.port,
      user: this.config.user,
      password: this.config.pass,
      secure: this.config.protocol === 'ftps',
    });
  }
  async list(remotePath) {
    const items = await this.client.list(remotePath);
    return items.map(it => ({
      name: it.name,
      isDir: it.isDirectory || it.type === 2,
      size: it.size,
      mtime: it.modifiedAt || null, // basic-ftp may or may not return mtime in LIST
    }));
  }
  async readFile(remotePath) {
    const bs = new BufferStream();
    await this.client.downloadTo(bs, remotePath);
    return bs.data;
  }
  async mtime(remotePath) {
    try {
      const r = await this.client.send(`MDTM ${remotePath}`);
      const m = r.message && r.message.match(/(\d{14})/);
      if (m) {
        const s = m[1];
        return new Date(
          `${s.slice(0,4)}-${s.slice(4,6)}-${s.slice(6,8)}T${s.slice(8,10)}:${s.slice(10,12)}:${s.slice(12,14)}Z`
        );
      }
    } catch {}
    return null;
  }
  async close() { this.client.close(); }
}

class SftpAdapter {
  // SFTP via ssh2-sftp-client.
  constructor(config) {
    this.config = config;
    const SftpClient = require('ssh2-sftp-client');
    this.client = new SftpClient();
  }
  async connect() {
    const opts = {
      host: this.config.host,
      port: this.config.port,
      username: this.config.user,
      password: this.config.pass,
      readyTimeout: 20000,
    };
    // Optional private-key auth
    if (process.env.SFTP_KEY_PATH) {
      const fs = require('fs');
      opts.privateKey = fs.readFileSync(process.env.SFTP_KEY_PATH);
      delete opts.password;
      if (process.env.SFTP_KEY_PASSPHRASE) opts.passphrase = process.env.SFTP_KEY_PASSPHRASE;
    }
    await this.client.connect(opts);
  }
  async list(remotePath) {
    const items = await this.client.list(remotePath);
    // ssh2-sftp-client: type 'd' = dir, '-' = file, 'l' = link
    return items.map(it => ({
      name: it.name,
      isDir: it.type === 'd',
      size: it.size,
      mtime: it.modifyTime ? new Date(it.modifyTime) : null,
    }));
  }
  async readFile(remotePath) {
    // get() without destination returns a Buffer
    return await this.client.get(remotePath);
  }
  async mtime(remotePath) {
    try {
      const stat = await this.client.stat(remotePath);
      return stat.modifyTime ? new Date(stat.modifyTime) : null;
    } catch {}
    return null;
  }
  async close() { await this.client.end(); }
}

function createAdapter(config) {
  if (config.protocol === 'sftp') return new SftpAdapter(config);
  return new BasicFtpAdapter(config);
}

// =========================================================================
// Audit core. Protocol-agnostic; uses the adapter interface.
// =========================================================================

async function walk(adapter, dir, out, depth = 0, maxDepth = 5) {
  let list;
  try {
    list = await adapter.list(dir);
  } catch (e) {
    console.error(`  [WARN] could not list ${dir}: ${e.message}`);
    return;
  }
  for (const it of list) {
    const full = `${dir}/${it.name}`.replace(/\/+/g, '/');
    out.push({
      path: full,
      name: it.name,
      isDir: it.isDir,
      size: it.size,
      mtime: it.mtime || null,
      depth,
    });
    if (it.isDir && depth < maxDepth) {
      await walk(adapter, full, out, depth + 1, maxDepth);
    }
  }
}

function header(s) {
  console.log('\n' + '='.repeat(60));
  console.log(s);
  console.log('='.repeat(60));
}

(async () => {
  const adapter = createAdapter(C);

  console.log(`Connecting to ${C.host}:${C.port} (${C.protocol.toUpperCase()})...`);
  try {
    await adapter.connect();
  } catch (e) {
    console.error(`FATAL: could not connect - ${e.message}`);
    process.exit(2);
  }
  console.log(`OK connected as ${C.user}, auditing ${C.path}\n`);

  const items = [];
  await walk(adapter, C.path, items, 0);
  const files = items.filter(i => !i.isDir);
  const dirs = items.filter(i => i.isDir);

  const findings = {
    unexpected_root: [],
    suspicious_names: [],
    php_files: [],
    dot_files: [],
    htaccess_path: null,
    htaccess_content: null,
    recent_mods: [],
    php_with_hack: [],
  };

  for (const it of items) {
    const inRoot = (it.depth === 0);
    if (inRoot && !EXPECTED_ROOT.has(it.name) && !it.name.startsWith('.')) {
      findings.unexpected_root.push(it);
    }
    if (it.name.startsWith('.') && it.name !== '.htaccess' && it.name !== '.well-known') {
      findings.dot_files.push(it);
    }
    for (const re of SUSPICIOUS_NAMES) {
      if (re.test(it.name) || re.test(it.path)) {
        findings.suspicious_names.push({ ...it, pattern: re.source });
        break;
      }
    }
    if (!it.isDir && /\.(php|phtml|php5|phar)$/i.test(it.name)) {
      findings.php_files.push(it);
    }
    if (it.name === '.htaccess' && !it.isDir) {
      findings.htaccess_path = it.path;
    }
  }

  // mtime: SFTP la trae en list(); FTP no. Solo pedimos explicito si falta.
  const criticalForMtime = files.filter(f =>
    /\.(html?|php|txt|xml)$/i.test(f.name) || f.name === '.htaccess'
  ).slice(0, 200);

  for (const f of criticalForMtime) {
    let dt = f.mtime;
    if (!dt) dt = await adapter.mtime(f.path);
    if (dt) {
      const days = (Date.now() - dt.getTime()) / 86400000;
      f.mtime = dt;
      f.ageDays = Math.round(days);
      if (days < 90) findings.recent_mods.push(f);
    }
  }

  // Download and analyze the content of each PHP file
  for (const phpFile of findings.php_files) {
    if (phpFile.size > 500_000) {
      console.log(`  [SKIP] ${phpFile.path} too large (${phpFile.size}B), review by hand`);
      continue;
    }
    try {
      const buf = await adapter.readFile(phpFile.path);
      const txt = buf.toString('utf8');
      const matches = [];
      for (const p of PHP_HACK_PATTERNS) {
        if (p.re.test(txt)) matches.push(p.msg);
      }
      if (matches.length > 0) {
        findings.php_with_hack.push({ path: phpFile.path, size: phpFile.size, matches });
      }
    } catch (e) {
      console.error(`  [WARN] could not read ${phpFile.path}: ${e.message}`);
    }
  }

  // Download the full .htaccess
  if (findings.htaccess_path) {
    try {
      const buf = await adapter.readFile(findings.htaccess_path);
      findings.htaccess_content = buf.toString('utf8');
    } catch (e) {
      console.error(`  [WARN] could not read .htaccess: ${e.message}`);
    }
  }

  // ============= REPORT =============
  header('SUMMARY');
  console.log(`Protocol         : ${C.protocol.toUpperCase()}`);
  console.log(`Total files      : ${files.length}`);
  console.log(`Directories      : ${dirs.length}`);
  console.log(`Total bytes      : ${(files.reduce((s, f) => s + (f.size || 0), 0) / 1024 / 1024).toFixed(2)} MB`);

  header('UNEXPECTED FILES IN ROOT');
  if (findings.unexpected_root.length === 0) console.log('  (none) OK');
  else for (const f of findings.unexpected_root) console.log(`  ${f.isDir ? '[DIR] ' : '[FILE]'} ${f.path}  ${f.size || ''}B`);

  header('SUSPICIOUS NAMES');
  if (findings.suspicious_names.length === 0) console.log('  (none) OK');
  else for (const f of findings.suspicious_names) console.log(`  ${f.path}  match=${f.pattern}`);

  header('PHP FILES');
  if (findings.php_files.length === 0) console.log('  (none) OK');
  else for (const f of findings.php_files) console.log(`  ${f.path}  ${f.size}B`);

  header('PHP WITH HACK PATTERNS');
  if (findings.php_with_hack.length === 0) console.log('  (none) OK');
  else for (const f of findings.php_with_hack) {
    console.log(`  ${f.path}  ${f.size}B`);
    for (const m of f.matches) console.log(`    -> ${m}`);
  }

  header('DOTFILES (excluding .htaccess and .well-known)');
  if (findings.dot_files.length === 0) console.log('  (none) OK');
  else for (const f of findings.dot_files) console.log(`  ${f.path}  ${f.size}B`);

  header('FILES MODIFIED IN THE LAST 90 DAYS');
  if (findings.recent_mods.length === 0) console.log('  (none)');
  else {
    findings.recent_mods.sort((a, b) => a.ageDays - b.ageDays);
    for (const f of findings.recent_mods.slice(0, 100)) {
      console.log(`  ${f.path}  ${f.ageDays}d ago  ${f.size}B`);
    }
    if (findings.recent_mods.length > 100) {
      console.log(`  ... and ${findings.recent_mods.length - 100} more`);
    }
  }

  header('.htaccess (review for conditional redirects)');
  if (findings.htaccess_content) {
    console.log(findings.htaccess_content);
  } else {
    console.log('  (not found or unreadable)');
  }

  // Exit code: 0 if clean, 1 if critical findings, 2 already used for connect failures
  const hasCritical = findings.php_with_hack.length > 0 ||
                      findings.suspicious_names.length > 0;
  await adapter.close();
  process.exit(hasCritical ? 1 : 0);
})().catch(e => {
  console.error('FATAL:', e);
  process.exit(2);
});
