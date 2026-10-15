#!/usr/bin/env node

/**
 * @authoritydmc/trust-cert
 * Zero-dependency CLI to inspect, extract, and install TLS certificates into
 * Windows, macOS, and Linux OS trust stores.
 *
 * Usage:
 *   npx @authoritydmc/trust-cert https://rajlab.lan
 *   npx @authoritydmc/trust-cert rajlab.lan:443 --yes
 */

const tls = require('tls');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { execSync } = require('child_process');

// ANSI formatting helpers
const bold = (s) => `\x1b[1m${s}\x1b[0m`;
const green = (s) => `\x1b[32m${s}\x1b[0m`;
const cyan = (s) => `\x1b[36m${s}\x1b[0m`;
const yellow = (s) => `\x1b[33m${s}\x1b[0m`;
const red = (s) => `\x1b[31m${s}\x1b[0m`;
const dim = (s) => `\x1b[2m${s}\x1b[0m`;

function printHelp() {
  console.log(`
${bold('trust-cert')} - Extract and install TLS/SSL certificates into OS trust stores.

${bold('USAGE:')}
  npx @authoritydmc/trust-cert <target> [options]

${bold('ARGUMENTS:')}
  <target>          URL or host[:port] (e.g. https://rajlab.lan, rajlab.lan:443, 192.168.0.200)

${bold('OPTIONS:')}
  -y, --yes         Automatically confirm and install without prompting
  -u, --user        Install to Current User store instead of System (Windows only, no admin needed)
  -o, --out <path>  Save the extracted certificate to a specific .crt/.pem file
  --ip <ip>         Directly connect to a custom IP address (e.g. 192.168.0.200 or 127.0.0.1) while preserving SNI
  -a, --all         Install entire certificate chain (both leaf and root CAs)
  -s, --show-chain  Display full certificate chain hierarchy details
  -h, --help        Show this help message
  -v, --version     Show version number

${bold('EXAMPLES:')}
  npx @authoritydmc/trust-cert https://rajlab.lan
  npx @authoritydmc/trust-cert rajlab.lan:443 --yes
  npx @authoritydmc/trust-cert https://rajlab.lan --out ./lab-ca.crt
`);
}

function parseArgs(args) {
  const options = {
    target: null,
    yes: false,
    user: false,
    out: null,
    all: false,
    showChain: false,
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '-h' || a === '--help') {
      printHelp();
      process.exit(0);
    }
    if (a === '-v' || a === '--version') {
      const pkg = require('../package.json');
      console.log(`v${pkg.version}`);
      process.exit(0);
    }
    if (a === '-y' || a === '--yes') {
      options.yes = true;
    } else if (a === '-u' || a === '--user') {
      options.user = true;
    } else if (a === '-a' || a === '--all') {
      options.all = true;
    } else if (a === '-s' || a === '--show-chain') {
      options.showChain = true;
    } else if (a === '--ip') {
      options.ip = args[++i];
    } else if (a === '-o' || a === '--out') {
      options.out = args[++i];
    } else if (!a.startsWith('-') && !options.target) {
      options.target = a;
    }
  }

  return options;
}

function parseTarget(target) {
  if (!target) return null;
  let clean = target.trim();
  let port = 443;
  let host = clean;

  if (clean.startsWith('http://') || clean.startsWith('https://')) {
    try {
      const u = new URL(clean);
      host = u.hostname;
      port = u.port ? parseInt(u.port, 10) : (u.protocol === 'http:' ? 80 : 443);
    } catch {
      // Fallback manual parse
    }
  } else if (clean.includes(':')) {
    const parts = clean.split(':');
    host = parts[0];
    port = parseInt(parts[1], 10) || 443;
  }

  // Strip trailing slashes
  host = host.replace(/\/.*$/, '');
  return { host, port };
}

function derToPem(derBuffer) {
  const b64 = derBuffer.toString('base64').match(/.{1,64}/g).join('\n');
  return `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
}

function getFingerprint(derBuffer) {
  return crypto.createHash('sha256').update(derBuffer).digest('hex').match(/.{2}/g).join(':').toUpperCase();
}

function fetchCertChain(host, port, connectHost) {
  const targetHost = connectHost || host;
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      {
        host: targetHost,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: 8000,
      },
      () => {
        try {
          const peer = socket.getPeerCertificate(true);
          if (!peer || !peer.raw) {
            socket.destroy();
            return reject(new Error('No certificate received from host during TLS handshake.'));
          }

          // Traverse chain
          const chain = [];
          let cur = peer;
          const seen = new Set();

          while (cur && cur.raw) {
            const fp = getFingerprint(cur.raw);
            if (seen.has(fp)) break;
            seen.add(fp);

            chain.push({
              subject: cur.subject,
              issuer: cur.issuer,
              validFrom: cur.valid_from,
              validTo: cur.valid_to,
              fingerprint: fp,
              sans: cur.subjectaltname,
              raw: cur.raw,
              pem: derToPem(cur.raw),
              isSelfSigned: cur.fingerprint === (cur.issuerCertificate && cur.issuerCertificate.fingerprint) ||
                            (cur.subject && cur.issuer && cur.subject.CN === cur.issuer.CN),
            });

            if (cur.issuerCertificate && cur.issuerCertificate !== cur) {
              cur = cur.issuerCertificate;
            } else {
              break;
            }
          }

          socket.end();
          resolve(chain);
        } catch (err) {
          socket.destroy();
          reject(err);
        }
      }
    );

    socket.on('error', (err) => reject(err));
    socket.on('timeout', () => {
      socket.destroy();
      reject(new Error(`Connection to ${host}:${port} timed out after 8s.`));
    });
  });
}

function detectOS() {
  const p = process.platform;
  if (p === 'win32') return { platform: 'win32', name: 'Windows' };
  if (p === 'darwin') return { platform: 'darwin', name: 'macOS' };
  if (p === 'linux') {
    let distro = 'Linux (Generic)';
    try {
      if (fs.existsSync('/etc/os-release')) {
        const osRel = fs.readFileSync('/etc/os-release', 'utf8');
        const match = osRel.match(/PRETTY_NAME="?([^"\n]+)"?/);
        if (match) distro = match[1];
      }
    } catch {}
    return { platform: 'linux', name: distro };
  }
  return { platform: p, name: p };
}

function askConfirmation(question) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    rl.question(question, (ans) => {
      rl.close();
      resolve(ans.trim().toLowerCase() === 'y' || ans.trim().toLowerCase() === 'yes');
    });
  });
}

function installCert(certPem, certName, osInfo, userOnly) {
  const tmpDir = os.tmpdir();
  const safeName = certName.replace(/[^a-zA-Z0-9_-]/g, '_');
  const tempPath = path.join(tmpDir, `${safeName}_trust_${Date.now()}.crt`);

  fs.writeFileSync(tempPath, certPem, { mode: 0o644 });

  try {
    if (osInfo.platform === 'win32') {
      const store = userOnly ? '-user Root' : 'Root';
      const cmd = `certutil -addstore ${store} "${tempPath}"`;
      console.log(dim(`> ${cmd}`));
      execSync(cmd, { stdio: 'inherit' });
      return true;
    }

    if (osInfo.platform === 'darwin') {
      const cmd = `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "${tempPath}"`;
      console.log(dim(`> ${cmd}`));
      execSync(cmd, { stdio: 'inherit' });
      return true;
    }

    if (osInfo.platform === 'linux') {
      // Ubuntu / Debian
      if (fs.existsSync('/usr/local/share/ca-certificates')) {
        const targetPath = `/usr/local/share/ca-certificates/${safeName}.crt`;
        console.log(dim(`> sudo cp "${tempPath}" "${targetPath}" && sudo update-ca-certificates`));
        execSync(`sudo cp "${tempPath}" "${targetPath}" && sudo update-ca-certificates`, { stdio: 'inherit' });
        return true;
      }
      // RHEL / Fedora / CentOS
      if (fs.existsSync('/etc/pki/ca-trust/source/anchors')) {
        const targetPath = `/etc/pki/ca-trust/source/anchors/${safeName}.crt`;
        console.log(dim(`> sudo cp "${tempPath}" "${targetPath}" && sudo update-ca-trust`));
        execSync(`sudo cp "${tempPath}" "${targetPath}" && sudo update-ca-trust`, { stdio: 'inherit' });
        return true;
      }
      // Arch Linux
      if (fs.existsSync('/etc/ca-certificates/trust-source/anchors')) {
        console.log(dim(`> sudo trust anchor "${tempPath}"`));
        execSync(`sudo trust anchor "${tempPath}"`, { stdio: 'inherit' });
        return true;
      }

      throw new Error('Unsupported Linux distribution certificate store path.');
    }

    throw new Error(`Auto-installation not supported directly on platform: ${osInfo.platform}`);
  } finally {
    try {
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
    } catch {}
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));

  if (!options.target) {
    console.error(red('Error: Target host or URL is required.\n'));
    printHelp();
    process.exit(1);
  }

  const parsed = parseTarget(options.target);
  const osInfo = detectOS();

  console.log(`\n🔒 ${bold('trust-cert')} v1.0.0 by RajLabs (@authoritydmc)`);
  console.log(`Connecting to ${cyan(parsed.host)}:${cyan(parsed.port)} over TLS...`);

  let chain;
  let connectHost = options.ip;
  try {
    chain = await fetchCertChain(parsed.host, parsed.port, connectHost);
  } catch (err) {
    if (!connectHost && (parsed.host.endsWith('.lan') || parsed.host.endsWith('.local') || parsed.host === 'rajlab')) {
      try {
        console.log(dim(`DNS resolution failed for ${parsed.host}. Trying fallback to 127.0.0.1...`));
        chain = await fetchCertChain(parsed.host, parsed.port, '127.0.0.1');
      } catch {
        try {
          console.log(dim(`Trying fallback to 192.168.0.200...`));
          chain = await fetchCertChain(parsed.host, parsed.port, '192.168.0.200');
        } catch {
          console.error(red(`\n❌ Failed to connect or retrieve TLS certificate:`));
          console.error(err.message);
          process.exit(1);
        }
      }
    } else {
      console.error(red(`\n❌ Failed to connect or retrieve TLS certificate:`));
      console.error(err.message);
      process.exit(1);
    }
  }

  console.log(`✅ Handshake successful. Retrieved ${bold(chain.length)} certificate(s) in chain.\n`);

  // Target certificate to trust:
  // If chain length > 1, the root/signing CA is at the top of the chain.
  // If chain length == 1, the leaf cert itself is the target (self-signed).
  const rootCert = chain[chain.length - 1];
  const leafCert = chain[0];

  console.log(bold('══════════════════════════════════════════════════════════════════════════════'));
  console.log(`  ${bold('CERTIFICATE TO TRUST:')} ${green(rootCert.subject.CN || 'Certificate')}`);
  console.log(bold('══════════════════════════════════════════════════════════════════════════════'));
  console.log(`  ${bold('Type:')}         ${chain.length > 1 ? yellow('Root / Intermediate CA (Trust Anchor)') : cyan('Server Certificate (Self-Signed)')}`);
  console.log(`  ${bold('Subject:')}      CN=${rootCert.subject.CN || '-'}, O=${rootCert.subject.O || '-'}`);
  console.log(`  ${bold('Issuer:')}       CN=${rootCert.issuer.CN || '-'}, O=${rootCert.issuer.O || '-'}`);
  console.log(`  ${bold('Valid From:')}   ${rootCert.validFrom}`);
  console.log(`  ${bold('Valid Until:')}  ${rootCert.validTo}`);
  console.log(`  ${bold('SHA-256:')}      ${cyan(rootCert.fingerprint)}`);
  if (leafCert.sans && leafCert !== rootCert) {
    console.log(`  ${bold('Leaf SANs:')}    ${dim(leafCert.sans)}`);
  }
  console.log(bold('──────────────────────────────────────────────────────────────────────────────'));
  console.log(`  ${bold('Detected OS:')}  ${green(osInfo.name)}`);
  console.log(bold('══════════════════════════════════════════════════════════════════════════════\n'));

  // Save to file if requested
  if (options.out) {
    const outPath = path.resolve(options.out);
    fs.writeFileSync(outPath, rootCert.pem, 'utf8');
    console.log(`💾 Certificate exported to: ${cyan(outPath)}`);
    if (!options.yes) {
      process.exit(0);
    }
  }

  // Ask confirmation before installing
  let shouldInstall = options.yes;
  if (!shouldInstall) {
    const prompt = `Do you want to install and trust this certificate in your ${bold(osInfo.name)} system store? [y/N]: `;
    shouldInstall = await askConfirmation(prompt);
  }

  if (!shouldInstall) {
    console.log(yellow('\nInstallation skipped. Certificate was not installed.'));
    console.log(`Tip: Use ${bold('--out <file.crt>')} to export the certificate to disk manually.`);
    process.exit(0);
  }

  console.log(`\n⚙️  Installing certificate into ${bold(osInfo.name)} trust store...`);
  try {
    const certName = rootCert.subject.CN || parsed.host;
    installCert(rootCert.pem, certName, osInfo, options.user);
    console.log(`\n🎉 ${green('SUCCESS:')} Certificate has been installed and is now trusted by your system!`);
    console.log(`   Browsers (Chrome, Edge, Safari, Brave) will now securely load https://${parsed.host} without warnings.\n`);
  } catch (err) {
    console.error(red(`\n❌ Failed to install certificate: ${err.message}`));
    console.log(yellow(`\nManual installation alternative:`));
    console.log(`Run: ${bold(`npx @authoritydmc/trust-cert ${options.target} --out ./cert.crt`)} and import manually.`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error(red(`Unexpected error: ${err.message}`));
  process.exit(1);
});
