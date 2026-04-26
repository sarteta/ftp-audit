/**
 * Detection unit test. Loads the PHP_HACK_PATTERNS list from ftp-audit.js
 * and runs it against synthetic samples. Proves which patterns the script
 * catches and which it intentionally does not.
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert/strict');

// Ideally we'd import PHP_HACK_PATTERNS from ftp-audit.js, but it's defined
// inside the script body. Duplicate the list here so the test stays self
// contained. Keep this in sync with ftp-audit.js.
const PHP_HACK_PATTERNS = [
  { re: /eval\s*\(\s*base64_decode/i, msg: 'eval(base64_decode)' },
  { re: /eval\s*\(\s*gzinflate/i, msg: 'eval(gzinflate)' },
  { re: /eval\s*\(\s*str_rot13/i, msg: 'eval(str_rot13)' },
  { re: /assert\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)/i, msg: 'assert() over input' },
  { re: /\$_(POST|GET|REQUEST)\[[^\]]+\]\s*\(/i, msg: 'callable from HTTP input' },
  { re: /preg_replace\s*\([^,]+\/e[^,]*,/i, msg: 'preg_replace /e (eval)' },
  { re: /system\s*\(\s*\$_/i, msg: 'system() over input' },
  { re: /shell_exec\s*\(\s*\$_/i, msg: 'shell_exec() over input' },
  { re: /passthru\s*\(\s*\$_/i, msg: 'passthru() over input' },
  { re: /file_put_contents\s*\([^,]+,\s*\$_/i, msg: 'file_put_contents over input' },
  { re: /move_uploaded_file/i, msg: 'upload handler (review context)' },
  { re: /mail\s*\(\s*\$_(POST|GET|REQUEST)/i, msg: 'mail() open relay' },
  { re: /\$[a-zA-Z_]+\s*=\s*["'][a-zA-Z0-9+/=]{500,}["']/i, msg: 'long b64 string (likely obfuscated payload)' },
  { re: /\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/i, msg: 'hex-encoded payload' },
];

function scan(content) {
  return PHP_HACK_PATTERNS.filter(p => p.re.test(content)).map(p => p.msg);
}

const samples = path.join(__dirname, 'samples');
const cases = [
  { file: 'benign-contact-form.php',     expectMatch: false, mustHave: [] },
  { file: 'backdoor-eval-base64.php',    expectMatch: true,  mustHave: ['eval(base64_decode)'] },
  { file: 'backdoor-assert-input.php',   expectMatch: true,  mustHave: ['assert() over input'] },
  { file: 'backdoor-preg-eval.php',      expectMatch: true,  mustHave: ['preg_replace /e (eval)'] },
  { file: 'backdoor-shell-exec.php',     expectMatch: true,  mustHave: ['shell_exec() over input', 'system() over input'] },
  { file: 'backdoor-mail-open-relay.php', expectMatch: true, mustHave: ['mail() open relay'] },
  { file: 'backdoor-mail-indirect-evasion.php', expectMatch: false, mustHave: [] },
  { file: 'backdoor-callable-input.php', expectMatch: true,  mustHave: ['callable from HTTP input'] },
  { file: 'backdoor-gzinflate.php',      expectMatch: true,  mustHave: ['eval(gzinflate)'] },
  { file: 'backdoor-obfuscated-tricky.php', expectMatch: false, mustHave: [] }, // admitted limitation
];

let failed = 0;
let passed = 0;
console.log('\n=== detection test against synthetic samples ===\n');
for (const c of cases) {
  const content = fs.readFileSync(path.join(samples, c.file), 'utf8');
  const matches = scan(content);
  const ok = c.expectMatch ? matches.length > 0 : matches.length === 0;
  const mustHaveOk = c.mustHave.every(m => matches.includes(m));
  if (ok && mustHaveOk) {
    console.log(`  PASS  ${c.file}`);
    if (matches.length > 0) {
      for (const m of matches) console.log(`         -> ${m}`);
    } else {
      console.log(`         -> (no match, as expected)`);
    }
    passed++;
  } else {
    console.log(`  FAIL  ${c.file}`);
    console.log(`         expectMatch=${c.expectMatch} actual matches=${JSON.stringify(matches)}`);
    console.log(`         mustHave=${JSON.stringify(c.mustHave)}`);
    failed++;
  }
}

console.log(`\nResult: ${passed} passed, ${failed} failed of ${cases.length}\n`);
process.exit(failed > 0 ? 1 : 0);
