#!/usr/bin/env node
/**
 * ftp-audit.js
 * Auditoria READ-ONLY de un sitio web servido sobre hosting compartido via FTP.
 * Detecta los vectores tipicos de SEO injection / pharma hack / japanese keyword hack.
 *
 * Uso:
 *   1. Copia .env.example a .env y completa credenciales
 *   2. npm install
 *   3. node ftp-audit.js
 *
 * Que hace (todo read-only, NO descarga ni modifica nada del server):
 *   - Walk recursivo del filesystem remoto via FTP
 *   - MDTM por archivo para fechas reales (LIST en muchos servers no las da)
 *   - Pattern matching para backdoors PHP conocidos
 *   - Whitelist de archivos esperados, todo lo demas se marca
 *   - Heuristicas de nombre (shell.php, c99.php, .suspected, .bak, wp-* en sitios sin WP)
 *   - Lectura de .htaccess para detectar redirects condicionales
 *   - Reporte estructurado por categoria
 *
 * Licencia: MIT. Usalo, modificalo, compartilo.
 */

require('dotenv').config();
const ftp = require('basic-ftp');
const { Writable } = require('stream');

const C = {
  host: process.env.FTP_HOST,
  user: process.env.FTP_USER,
  pass: process.env.FTP_PASS,
  path: process.env.FTP_PATH || '/public_html',
  port: parseInt(process.env.FTP_PORT || '21', 10),
  secure: (process.env.FTP_SECURE || 'false').toLowerCase() === 'true',
};

if (!C.host || !C.user || !C.pass) {
  console.error('ERROR: faltan FTP_HOST / FTP_USER / FTP_PASS en .env');
  console.error('Copia .env.example a .env y completa los valores.');
  process.exit(1);
}

// Whitelist de archivos/carpetas esperados en root.
// Personalizalo segun tu sitio. Todo lo demas en root se reporta como "no esperado".
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

class BufferStream extends Writable {
  constructor() { super(); this.chunks = []; }
  _write(chunk, _, cb) { this.chunks.push(chunk); cb(); }
  get data() { return Buffer.concat(this.chunks); }
}

async function downloadToBuffer(client, remote) {
  const bs = new BufferStream();
  await client.downloadTo(bs, remote);
  return bs.data;
}

async function safeMdtm(client, remote) {
  try {
    const r = await client.send(`MDTM ${remote}`);
    const m = r.message && r.message.match(/(\d{14})/);
    if (m) {
      const s = m[1];
      return new Date(`${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`);
    }
  } catch {}
  return null;
}

async function walk(client, dir, out, depth = 0, maxDepth = 5) {
  let list;
  try {
    list = await client.list(dir);
  } catch (e) {
    console.error(`  [WARN] no pude listar ${dir}: ${e.message}`);
    return;
  }
  for (const it of list) {
    const full = `${dir}/${it.name}`.replace(/\/+/g, '/');
    const isDir = it.isDirectory || it.type === 2;
    out.push({ path: full, name: it.name, isDir, size: it.size, depth });
    if (isDir && depth < maxDepth) {
      await walk(client, full, out, depth + 1, maxDepth);
    }
  }
}

function header(s) {
  console.log('\n' + '='.repeat(60));
  console.log(s);
  console.log('='.repeat(60));
}

(async () => {
  const client = new ftp.Client(20000);
  client.ftp.verbose = false;

  console.log(`Conectando a ${C.host}:${C.port} (${C.secure ? 'FTPS' : 'FTP'})...`);
  try {
    await client.access({
      host: C.host, port: C.port, user: C.user, password: C.pass, secure: C.secure,
    });
  } catch (e) {
    console.error(`FATAL: no me pude conectar - ${e.message}`);
    process.exit(1);
  }
  console.log(`OK conectado como ${C.user}, auditando ${C.path}\n`);

  const items = [];
  await walk(client, C.path, items, 0);
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
    // Whitelist en root (depth 0 y 1 dentro del path base)
    const inRoot = (it.depth === 0);
    if (inRoot && !EXPECTED_ROOT.has(it.name) && !it.name.startsWith('.')) {
      findings.unexpected_root.push(it);
    }
    // Dotfiles
    if (it.name.startsWith('.') && it.name !== '.htaccess' && it.name !== '.well-known') {
      findings.dot_files.push(it);
    }
    // Suspicious names
    for (const re of SUSPICIOUS_NAMES) {
      if (re.test(it.name) || re.test(it.path)) {
        findings.suspicious_names.push({ ...it, pattern: re.source });
        break;
      }
    }
    // PHP files
    if (!it.isDir && /\.(php|phtml|php5|phar)$/i.test(it.name)) {
      findings.php_files.push(it);
    }
    // .htaccess captura
    if (it.name === '.htaccess' && !it.isDir) {
      findings.htaccess_path = it.path;
    }
  }

  // MDTM en archivos clave (.html, .php, .htaccess, .txt, .xml en root y subroot)
  const criticalForMdtm = files.filter(f =>
    /\.(html?|php|txt|xml)$/i.test(f.name) || f.name === '.htaccess'
  ).slice(0, 200);

  for (const f of criticalForMdtm) {
    const dt = await safeMdtm(client, f.path);
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
      const buf = await downloadToBuffer(client, phpFile.path);
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
      const buf = await downloadToBuffer(client, findings.htaccess_path);
      findings.htaccess_content = buf.toString('utf8');
    } catch (e) {
      console.error(`  [WARN] no pude leer .htaccess: ${e.message}`);
    }
  }

  // ============= REPORT =============
  header('RESUMEN');
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
  client.close();
  process.exit(hasCritical ? 1 : 0);
})().catch(e => {
  console.error('FATAL:', e);
  process.exit(2);
});
