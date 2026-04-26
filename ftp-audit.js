#!/usr/bin/env node
/**
 * ftp-audit.js
 * Auditoria READ-ONLY de un sitio web servido sobre hosting compartido.
 * Soporta tres protocolos:
 *   - SFTP (FTP sobre SSH, puerto 22)         <- recomendado, encriptado
 *   - FTPS (FTP sobre TLS, puerto 21 o 990)   <- encriptado
 *   - FTP plano (puerto 21)                   <- creds en cleartext, evitar
 *
 * Detecta los vectores tipicos de SEO injection / pharma hack / japanese
 * keyword hack / backdoors PHP. Todo read-only: NO descarga al disco local,
 * NO modifica nada en el server.
 *
 * Uso:
 *   1. Copia .env.example a .env y completa credenciales
 *   2. npm install
 *   3. node ftp-audit.js
 *
 * Licencia: MIT.
 */

require('dotenv').config();
const { Writable } = require('stream');

// Resolver protocolo. FTP_PROTOCOL gana sobre FTP_SECURE (legacy).
function resolveProtocol() {
  const explicit = (process.env.FTP_PROTOCOL || '').toLowerCase().trim();
  if (['sftp', 'ftps', 'ftp'].includes(explicit)) return explicit;
  // Backwards-compat: FTP_SECURE=true significa FTPS
  if ((process.env.FTP_SECURE || '').toLowerCase() === 'true') return 'ftps';
  return 'sftp'; // default seguro
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
  console.error('ERROR: faltan FTP_HOST / FTP_USER / FTP_PASS en .env');
  console.error('Copia .env.example a .env y completa los valores.');
  process.exit(1);
}

// Whitelist de archivos/carpetas esperados en root.
const EXPECTED_ROOT = new Set((process.env.EXPECTED_ROOT || [
  'index.html', 'index.php',
  'robots.txt', 'sitemap.xml', 'favicon.ico', '.htaccess',
  'css', 'js', 'img', 'images', 'assets', 'fonts',
].join(',')).split(',').map(s => s.trim()).filter(Boolean));

// Patrones sospechosos en nombre de archivo
const SUSPICIOUS_NAMES = [
  /pgsoft/i, /casino/i, /aposta/i, /jogo/i, /slot/i, /bingo/i, /poker/i,
  /viagra/i, /pharma/i, /pillen/i, /cialis/i, /levitra/i,
  /shell\.php/i, /c99\.php/i, /r57\.php/i, /webshell/i, /backdoor/i,
  /\.suspected$/i, /\.bak$/i, /\.old$/i, /\.orig$/i, /~$/,
  /^wp-/i, /wordpress/i,
];

// Patrones de hack en contenido PHP (cuando descarguemos los .php)
const PHP_HACK_PATTERNS = [
  { re: /eval\s*\(\s*base64_decode/i, msg: 'eval(base64_decode) - backdoor clasico' },
  { re: /eval\s*\(\s*gzinflate/i, msg: 'eval(gzinflate) - obfuscation' },
  { re: /eval\s*\(\s*str_rot13/i, msg: 'eval(str_rot13) - obfuscation' },
  { re: /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i, msg: 'assert() sobre input' },
  { re: /\$_(POST|GET|REQUEST)\[[^\]]+\]\s*\(/i, msg: 'callable desde input HTTP' },
  { re: /preg_replace\s*\([^,]+\/e[^,]*,/i, msg: 'preg_replace con modificador /e (eval)' },
  { re: /system\s*\(\s*\$_/i, msg: 'system() sobre input' },
  { re: /shell_exec\s*\(\s*\$_/i, msg: 'shell_exec() sobre input' },
  { re: /passthru\s*\(\s*\$_/i, msg: 'passthru() sobre input' },
  { re: /file_put_contents\s*\([^,]+,\s*\$_/i, msg: 'file_put_contents con input no sanitizado' },
  { re: /move_uploaded_file/i, msg: 'upload handler (revisar contexto)' },
  { re: /mail\s*\(\s*\$_(POST|GET|REQUEST)/i, msg: 'mail() con destinatario desde input (open relay)' },
  { re: /\$[a-zA-Z_]+\s*=\s*["'][a-zA-Z0-9+/=]{500,}["']/i, msg: 'String b64 muy largo (probable payload obfuscado)' },
  { re: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, msg: 'Hex-encoded payload sospechoso' },
];

// =========================================================================
// ADAPTERS por protocolo. Misma interfaz para que walk + analisis no cambien.
// =========================================================================

class BufferStream extends Writable {
  constructor() { super(); this.chunks = []; }
  _write(chunk, _, cb) { this.chunks.push(chunk); cb(); }
  get data() { return Buffer.concat(this.chunks); }
}

class BasicFtpAdapter {
  // Soporta FTP plano y FTPS via la libreria basic-ftp.
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
      mtime: it.modifiedAt || null, // basic-ftp puede o no traerlo en LIST
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
  // Soporta SFTP via ssh2-sftp-client.
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
    // Soporte opcional de private key
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
    // get() sin destination devuelve Buffer
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
// AUDITORIA. Independiente del protocolo, usa el adapter.
// =========================================================================

async function walk(adapter, dir, out, depth = 0, maxDepth = 5) {
  let list;
  try {
    list = await adapter.list(dir);
  } catch (e) {
    console.error(`  [WARN] no pude listar ${dir}: ${e.message}`);
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

  console.log(`Conectando a ${C.host}:${C.port} (${C.protocol.toUpperCase()})...`);
  try {
    await adapter.connect();
  } catch (e) {
    console.error(`FATAL: no me pude conectar - ${e.message}`);
    process.exit(2);
  }
  console.log(`OK conectado como ${C.user}, auditando ${C.path}\n`);

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

  // Descargar y analizar contenido de cada PHP encontrado
  for (const phpFile of findings.php_files) {
    if (phpFile.size > 500_000) {
      console.log(`  [SKIP] ${phpFile.path} muy grande (${phpFile.size}B), revisar a mano`);
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
      console.error(`  [WARN] no pude leer ${phpFile.path}: ${e.message}`);
    }
  }

  // Descargar .htaccess completo
  if (findings.htaccess_path) {
    try {
      const buf = await adapter.readFile(findings.htaccess_path);
      findings.htaccess_content = buf.toString('utf8');
    } catch (e) {
      console.error(`  [WARN] no pude leer .htaccess: ${e.message}`);
    }
  }

  // ============= REPORT =============
  header('RESUMEN');
  console.log(`Protocolo        : ${C.protocol.toUpperCase()}`);
  console.log(`Archivos totales : ${files.length}`);
  console.log(`Directorios      : ${dirs.length}`);
  console.log(`Bytes totales    : ${(files.reduce((s, f) => s + (f.size || 0), 0) / 1024 / 1024).toFixed(2)} MB`);

  header('ARCHIVOS NO ESPERADOS EN ROOT');
  if (findings.unexpected_root.length === 0) console.log('  (ninguno) OK');
  else for (const f of findings.unexpected_root) console.log(`  ${f.isDir ? '[DIR] ' : '[FILE]'} ${f.path}  ${f.size || ''}B`);

  header('NOMBRES SOSPECHOSOS');
  if (findings.suspicious_names.length === 0) console.log('  (ninguno) OK');
  else for (const f of findings.suspicious_names) console.log(`  ${f.path}  match=${f.pattern}`);

  header('ARCHIVOS PHP');
  if (findings.php_files.length === 0) console.log('  (ninguno) OK');
  else for (const f of findings.php_files) console.log(`  ${f.path}  ${f.size}B`);

  header('PHP CON PATRONES DE HACK');
  if (findings.php_with_hack.length === 0) console.log('  (ninguno) OK');
  else for (const f of findings.php_with_hack) {
    console.log(`  ${f.path}  ${f.size}B`);
    for (const m of f.matches) console.log(`    -> ${m}`);
  }

  header('DOTFILES (excepto .htaccess y .well-known)');
  if (findings.dot_files.length === 0) console.log('  (ninguno) OK');
  else for (const f of findings.dot_files) console.log(`  ${f.path}  ${f.size}B`);

  header('ARCHIVOS MODIFICADOS EN ULTIMOS 90 DIAS');
  if (findings.recent_mods.length === 0) console.log('  (ninguno)');
  else {
    findings.recent_mods.sort((a, b) => a.ageDays - b.ageDays);
    for (const f of findings.recent_mods.slice(0, 100)) {
      console.log(`  ${f.path}  hace ${f.ageDays}d  ${f.size}B`);
    }
    if (findings.recent_mods.length > 100) {
      console.log(`  ... y ${findings.recent_mods.length - 100} mas`);
    }
  }

  header('.htaccess (revisar redirects condicionales)');
  if (findings.htaccess_content) {
    console.log(findings.htaccess_content);
  } else {
    console.log('  (no encontrado o ilegible)');
  }

  // Exit code: 0 si todo limpio, 1 si hubo hallazgos criticos
  const hasCritical = findings.php_with_hack.length > 0 ||
                      findings.suspicious_names.length > 0;
  await adapter.close();
  process.exit(hasCritical ? 1 : 0);
})().catch(e => {
  console.error('FATAL:', e);
  process.exit(2);
});
