#!/usr/bin/env node
'use strict';

// Node CLI, same interface as the Bash and Go ones: stdin in, stdout out.
const {encrypt, decrypt} = require('..');

function usage() {
  process.stderr.write(`Usage:
  ssh-agent-crypt [key]            < plaintext > encrypted
  ssh-agent-crypt -decrypt [key]   < encrypted > plaintext

Key can be:
  - path to a key file
  - key comment (e.g. "user@host")
  - SHA256 fingerprint
  - MD5 fingerprint
  - omitted -> SSH_AGENT_CRYPT_KEY, VAUTH_USER_IDENTITY, VAUTH_USER_MAIL,
               else first key from ssh-agent

Notes:
  - Encryption: AES-256-CBC + HMAC-SHA256
  - Format:
      ssh-agent-crypt:v3:<fingerprint>.<salt_b64>.<iv_hex>.<ciphertext_b64>.<mac_hex>
    (v2 and v1 payloads remain readable)
`);
  process.exit(1);
}

function drain(stream) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', chunk => chunks.push(chunk));
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', reject);
  });
}

async function main(args) {
  let mode = encrypt, key;
  if(args[0] === '-decrypt') {
    mode = decrypt;
    args = args.slice(1);
  }
  if(args.length > 1 || (args[0] || '').startsWith('-'))
    usage();
  key = args[0] || undefined;

  // Read upstream completely before contacting the agent.
  const input = await drain(process.stdin);
  const output = await mode(input, key);
  await new Promise((resolve, reject) => process.stdout.write(output, err => err ? reject(err) : resolve()));
}

main(process.argv.slice(2)).catch(err => {
  process.stderr.write(`${err.message}\n`);
  process.exit(1);
});
