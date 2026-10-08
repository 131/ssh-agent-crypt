'use strict';

const fs = require('fs');
const {promisify} = require('util');
const {utils: {parseKey}} = require('ssh2');
const {createAgent} = require('ssh2/lib/agent');
const {randomBytes, createHash, createHmac, createCipheriv, createDecipheriv, timingSafeEqual} = require('crypto');

const PREFIX = 'ssh-agent-crypt:v1:';

async function resolveKey(selector, agent) {
  if(selector && fs.existsSync(selector)) {
    let key = parseKey(fs.readFileSync(selector));
    if(key instanceof Error)
      throw key;
    if(Array.isArray(key))
      key = key[0];
    return key;
  }
  const keys = await promisify(agent.getIdentities.bind(agent))();
  if(!keys.length)
    throw new Error('No keys in ssh-agent');
  if(!selector)
    return keys[0];
  for(const key of keys) {
    const blob = key.getPublicSSH();
    const sha256 = 'SHA256:' + createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
    const md5 = createHash('md5').update(blob).digest('hex');
    if(key.comment === selector || sha256 === selector || md5 === selector.replace(/^MD5:/, '').replace(/:/g, ''))
      return key;
  }
  throw new Error(`Key not found: ${selector}`);
}

function sshString(value) {
  const bytes = Buffer.from(value);
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

async function deriveKeys(salt, selector, {env = process.env} = {}) {
  const agent = createAgent(env.SSH_AUTH_SOCK || (process.platform === 'win32' ? 'pageant' : ''));
  const key = await resolveKey(selector, agent);
  if(!['ssh-rsa', 'ssh-ed25519'].includes(key.type))
    throw new Error(`Unsupported key type: ${key.type}`);

  // Reproduce OpenSSH's SSHSIG envelope, not just the raw agent signature.
  const fields = [sshString('file'), sshString(''), sshString('sha512')];
  const message = createHash('sha512').update(salt).digest();
  const data = Buffer.concat([Buffer.from('SSHSIG'), ...fields, sshString(message)]);
  let signature;
  if(key.isPrivateKey()) {
    signature = key.sign(data, key.type === 'ssh-rsa' ? 'sha512' : undefined);
    if(signature instanceof Error)
      throw signature;
  } else {
    signature = await promisify(agent.sign.bind(agent))(key, data, {hash: 'sha512'});
  }
  const algorithm = key.type === 'ssh-rsa' ? 'rsa-sha2-512' : key.type;
  const version = Buffer.from([0, 0, 0, 1]);
  const blob = Buffer.concat([
    Buffer.from('SSHSIG'), version, sshString(key.getPublicSSH()), ...fields,
    sshString(Buffer.concat([sshString(algorithm), sshString(signature)])),
  ]);
  const material = createHash('sha512').update(blob).digest('hex');
  return {
    enc: createHash('sha256').update('enc:' + material).digest(),
    mac: createHash('sha256').update('mac:' + material).digest(),
  };
}

exports.encrypt = async function(input, key, options) {
  const salt = randomBytes(32).toString('base64');
  const iv = randomBytes(16);
  const keys = await deriveKeys(salt, key, options);
  const cipher = createCipheriv('aes-256-cbc', keys.enc, iv);
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]).toString('base64');
  const payload = `${salt}.${iv.toString('hex')}.${ciphertext}`;
  const mac = createHmac('sha256', keys.mac).update(payload).digest('hex');
  return `${PREFIX}${payload}.${mac}\n`;
};

exports.decrypt = async function(input, key, options) {
  const line = input.toString().split('\n')[0];
  if(!line.startsWith(PREFIX))
    throw new Error('Unsupported format header');
  const parts = line.slice(PREFIX.length).split('.');
  if(parts.length !== 4)
    throw new Error('Invalid payload');
  const [salt, iv, ciphertext, mac] = parts;
  const keys = await deriveKeys(salt, key, options);
  const expected = createHmac('sha256', keys.mac).update(`${salt}.${iv}.${ciphertext}`).digest();
  const actual = Buffer.from(mac, 'hex');
  if(actual.length !== expected.length || !timingSafeEqual(actual, expected))
    throw new Error('Authentication failed');
  const decipher = createDecipheriv('aes-256-cbc', keys.enc, Buffer.from(iv, 'hex'));
  return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]).toString('utf8');
};
