const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const {spawnSync} = require("node:child_process");

const AgentClient = require("ssh-agent-js/client");

const REPO_ROOT = path.resolve(__dirname, "..");
const CLI_PATH = path.join(REPO_ROOT, "bin", "ssh-agent-crypt");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });

  if(result.error)
    throw result.error;

  return result;
}

function assertSuccess(result, label) {
  assert.equal(result.status, 0, label + " failed\nstdout:\n" + result.stdout + "\nstderr:\n" + result.stderr);
}

function createKey(tmpDir, comment, type = "ed25519") {
  const keyBase = comment.replace(/[^a-z0-9_-]/gi, "_");
  const keyPath = path.join(tmpDir, keyBase);
  const result = run("ssh-keygen", ["-q", "-t", type, "-N", "", "-C", comment, "-f", keyPath]);
  assertSuccess(result, "ssh-keygen " + comment);
  return {
    comment,
    privateKey: keyPath,
    publicKey: keyPath + ".pub",
  };
}

function startAgent(env) {
  const result = run("ssh-agent", ["-s"], {env});
  assertSuccess(result, "ssh-agent -s");

  const sock = result.stdout.match(/SSH_AUTH_SOCK=([^;]+);/);
  const pid = result.stdout.match(/SSH_AGENT_PID=([0-9]+);/);
  assert.ok(sock, "Unable to parse SSH_AUTH_SOCK from:\n" + result.stdout);
  assert.ok(pid, "Unable to parse SSH_AGENT_PID from:\n" + result.stdout);

  return {
    ...env,
    SSH_AUTH_SOCK: sock[1],
    SSH_AGENT_PID: pid[1],
  };
}

function stopAgent(env) {
  const result = run("ssh-agent", ["-k"], {env});
  assertSuccess(result, "ssh-agent -k");
}

function addKey(env, keyPath) {
  const result = run("ssh-add", [keyPath], {env});
  assertSuccess(result, "ssh-add " + keyPath);
}

async function listAgentKeys(env) {
  const socket = net.connect(env.SSH_AUTH_SOCK);
  const client = new AgentClient(socket);

  try {
    return await client.list_keys();
  } finally {
    socket.end();
    socket.destroy();
  }
}

async function withAgent(callback) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-agent-crypt-"));
  const env = startAgent({...process.env});

  try {
    await callback({tmpDir, env});
  } finally {
    stopAgent(env);
    fs.rmSync(tmpDir, {recursive: true, force: true});
  }
}

test("round-trips with the first ssh-agent identity", async () => {
  await withAgent(async ({tmpDir, env}) => {
    const alpha = createKey(tmpDir, "alpha@test");
    addKey(env, alpha.privateKey);

    const listed = await listAgentKeys(env);
    assert.equal(Object.keys(listed).length, 1);
    assert.equal(Object.values(listed)[0].comment, "alpha@test");

    const plaintext = "hello from bash\nline2\n";
    const encrypted = run("bash", [CLI_PATH], {env, input: plaintext});
    assertSuccess(encrypted, "encrypt default key");

    const lines = encrypted.stdout.trimEnd().split("\n");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /^ssh-agent-crypt:v2:SHA256:[A-Za-z0-9+/]{43}\.[A-Za-z0-9+/=]+\.[0-9a-f]+\.[A-Za-z0-9+/=]+\.[0-9a-f]+$/);

    const decrypted = run("bash", [CLI_PATH, "-decrypt"], {env, input: encrypted.stdout});
    assertSuccess(decrypted, "decrypt default key");
    assert.equal(decrypted.stdout, plaintext);
  });
});

test("accepts a key comment as selector", async () => {
  await withAgent(async ({tmpDir, env}) => {
    const alpha = createKey(tmpDir, "alpha@test");
    const beta = createKey(tmpDir, "beta@test");
    addKey(env, alpha.privateKey);
    addKey(env, beta.privateKey);

    const plaintext = "comment selection works\n";
    const encrypted = run("bash", [CLI_PATH, "beta@test"], {env, input: plaintext});
    assertSuccess(encrypted, "encrypt by comment");

    const decrypted = run("bash", [CLI_PATH, "-decrypt", "beta@test"], {env, input: encrypted.stdout});
    assertSuccess(decrypted, "decrypt by comment");
    assert.equal(decrypted.stdout, plaintext);
  });
});

test("accepts an MD5 fingerprint reported by ssh-agent-js", async () => {
  await withAgent(async ({tmpDir, env}) => {
    const alpha = createKey(tmpDir, "alpha@test");
    const beta = createKey(tmpDir, "beta@test");
    addKey(env, alpha.privateKey);
    addKey(env, beta.privateKey);

    const listed = Object.values(await listAgentKeys(env));
    const betaEntry = listed.find((entry) => entry.comment === "beta@test");
    assert.ok(betaEntry, "beta@test not found in " + JSON.stringify(listed, null, 2));

    const plaintext = "md5 fingerprint selection works\n";
    const encrypted = run("bash", [CLI_PATH, betaEntry.fingerprint], {env, input: plaintext});
    assertSuccess(encrypted, "encrypt by md5 fingerprint");

    const decrypted = run("bash", [CLI_PATH, "-decrypt", betaEntry.fingerprint], {env, input: encrypted.stdout});
    assertSuccess(decrypted, "decrypt by md5 fingerprint");
    assert.equal(decrypted.stdout, plaintext);
  });
});


test("round-trips with an RSA identity", async () => {
  await withAgent(async ({tmpDir, env}) => {
    const rsa = createKey(tmpDir, "rsa@test", "rsa");
    addKey(env, rsa.privateKey);

    const plaintext = "rsa works too\n";
    const encrypted = run("bash", [CLI_PATH], {env, input: plaintext});
    assertSuccess(encrypted, "encrypt with rsa key");

    const decrypted = run("bash", [CLI_PATH, "-decrypt"], {env, input: encrypted.stdout});
    assertSuccess(decrypted, "decrypt with rsa key");
    assert.equal(decrypted.stdout, plaintext);
  });
});

test("rejects ecdsa identities", async () => {
  await withAgent(async ({tmpDir, env}) => {
    const ecdsa = createKey(tmpDir, "ecdsa@test", "ecdsa");
    addKey(env, ecdsa.privateKey);

    const result = run("bash", [CLI_PATH], {env, input: "should fail\n"});
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Unsupported key type: ecdsa-sha2-/);
  });
});

test("round-trips with a private key path without ssh-agent", () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-agent-crypt-"));
  const env = {...process.env};
  delete env.SSH_AUTH_SOCK;
  delete env.SSH_AGENT_PID;

  try {
    const local = createKey(tmpDir, "local@test");
    const plaintext = "local private key works\n";
    const encrypted = run("bash", [CLI_PATH, local.privateKey], {env, input: plaintext});
    assertSuccess(encrypted, "encrypt with private key path");

    const decrypted = run("bash", [CLI_PATH, "-decrypt", local.privateKey], {env, input: encrypted.stdout});
    assertSuccess(decrypted, "decrypt with private key path");
    assert.equal(decrypted.stdout, plaintext);
  } finally {
    fs.rmSync(tmpDir, {recursive: true, force: true});
  }
});

test("rejects tampered ciphertext with an HMAC failure", async () => {
  await withAgent(async ({tmpDir, env}) => {
    const alpha = createKey(tmpDir, "alpha@test");
    addKey(env, alpha.privateKey);

    const plaintext = "tamper must fail\n";
    const encrypted = run("bash", [CLI_PATH], {env, input: plaintext});
    assertSuccess(encrypted, "encrypt for tamper test");

    const payload = encrypted.stdout.trim();
    const last = payload.slice(-1);
    const tampered = payload.slice(0, -1) + (last === "A" ? "B" : "A") + "\n";

    const decrypted = run("bash", [CLI_PATH, "-decrypt"], {env, input: tampered});
    assert.notEqual(decrypted.status, 0);
    assert.match(decrypted.stderr, /Authentication failed/);
  });
});


test("Node API interoperates with the shipped CLI", async () => {
  const {encrypt, decrypt} = require("..");
  await withAgent(async ({tmpDir, env}) => {
    const alpha = createKey(tmpDir, "node@test");
    addKey(env, alpha.privateKey);
    const plaintext = "node API\nwithout a trailing newline";
    const armored = await encrypt(plaintext, "node@test", {env});
    assert.match(armored, /^ssh-agent-crypt:v2:/);
    assert.equal(await decrypt(armored, "node@test", {env}), plaintext);
    const decrypted = run("bash", [CLI_PATH, "-decrypt", "node@test"], {env, input: armored});
    assertSuccess(decrypted, "CLI decrypts Node armor");
    assert.equal(decrypted.stdout, plaintext);
    const encrypted = run("bash", [CLI_PATH, "node@test"], {env, input: plaintext});
    assertSuccess(encrypted, "CLI encrypts for Node");
    assert.equal(await decrypt(encrypted.stdout, "node@test", {env}), plaintext);
    await assert.rejects(() => decrypt(armored.replace(/.$/m, "x"), "node@test", {env}), /Authentication failed/);
    await assert.rejects(() => encrypt(plaintext, "missing@test", {env}), /Key not found/);
  });
});

for(const type of ['ed25519', 'rsa']) {
  test(`canonical JS/Bash cross-decryption for ${type} and all key selectors`, async () => {
    const {encrypt, decrypt} = require('..');
    await withAgent(async ({tmpDir, env}) => {
      const alpha = createKey(tmpDir, 'alpha@test');
      const selected = createKey(tmpDir, `selected-${type}@test`, type);
      addKey(env, alpha.privateKey);
      addKey(env, selected.privateKey);
      const sha256 = run('ssh-keygen', ['-lf', selected.publicKey]).stdout.split(/\s+/)[1];
      const md5 = run('ssh-keygen', ['-E', 'md5', '-lf', selected.publicKey]).stdout.split(/\s+/)[1];
      const selectors = [selected.comment, selected.publicKey, sha256, md5, md5.replace(/:/g, '').slice(3)];
      for(const selector of selectors) {
        const plaintext = `Unicode: coucou bibou 🐻\n${selector}`;
        const armor = await encrypt(plaintext, selector, {env});
        const bash = run('bash', [CLI_PATH, '-decrypt', selected.comment], {env, input: armor});
        assertSuccess(bash, 'Bash decrypts JS ' + selector);
        assert.equal(bash.stdout, plaintext);
        const encrypted = run('bash', [CLI_PATH, selected.comment], {env, input: plaintext});
        assertSuccess(encrypted, 'Bash encrypts');
        assert.equal(await decrypt(encrypted.stdout, selector, {env}), plaintext);
      }
      const empty = await encrypt('', undefined, {env});
      assert.equal(await decrypt(empty, undefined, {env}), '');
      const bashEmpty = run('bash', [CLI_PATH, '-decrypt'], {env, input: empty});
      assertSuccess(bashEmpty, 'empty ciphertext');
      assert.equal(bashEmpty.stdout, '');
      const wrong = await encrypt('secret', alpha.comment, {env});
      await assert.rejects(() => decrypt(wrong, selected.comment, {env}), /Authentication failed/);
    });
  });
}

test('JS private key mode interoperates without an agent', async () => {
  const {encrypt, decrypt} = require('..');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ssh-agent-crypt-node-'));
  const env = {...process.env, SSH_AUTH_SOCK: ''};
  try {
    const key = createKey(tmpDir, 'private@test');
    const armor = await encrypt('private key', key.privateKey, {env});
    const bash = run('bash', [CLI_PATH, '-decrypt', key.privateKey], {env, input: armor});
    assertSuccess(bash, 'private key Bash decrypt');
    assert.equal(bash.stdout, 'private key');
    const encrypted = run('bash', [CLI_PATH, key.privateKey], {env, input: 'reverse'});
    assertSuccess(encrypted, 'private key Bash encrypt');
    assert.equal(await decrypt(encrypted.stdout, key.privateKey, {env}), 'reverse');
  } finally {
    fs.rmSync(tmpDir, {recursive: true, force: true});
  }
});

test('JS rejects ECDSA, missing agents and malformed armor', async () => {
  const {encrypt, decrypt} = require('..');
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'ecdsa@test', 'ecdsa');
    addKey(env, key.privateKey);
    await assert.rejects(() => encrypt('secret', undefined, {env}), /Unsupported key type/);
    await assert.rejects(() => encrypt('secret', key.publicKey, {env}), /Unsupported key type/);
  });
  await assert.rejects(() => encrypt('secret', undefined, {env: {...process.env, SSH_AUTH_SOCK: ''}}));
  await assert.rejects(() => decrypt('plaintext'), /Unsupported format header/);
  await assert.rejects(() => decrypt('ssh-agent-crypt:v2:missing.parts'), /Invalid key fingerprint/);
});


test('JS encryption and decryption work with no executables on PATH', async () => {
  const {encrypt, decrypt} = require('..');
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'pure-js@test');
    addKey(env, key.privateKey);
    const options = {env: {...env, PATH: tmpDir}};
    const armor = await encrypt('no subprocess', undefined, options);
    assert.equal(await decrypt(armor, undefined, options), 'no subprocess');
  });
});

for(const type of ['ed25519', 'rsa']) {
  test(`v2 selects the embedded fingerprint after agent key reordering (${type})`, async () => {
    const {encrypt, decrypt} = require('..');
    await withAgent(async ({tmpDir, env}) => {
      const alpha = createKey(tmpDir, 'alpha@test');
      const beta = createKey(tmpDir, `beta-${type}@test`, type);
      addKey(env, beta.privateKey);
      addKey(env, alpha.privateKey);
      const jsArmor = await encrypt('from JS', undefined, {env});
      const bashArmor = run('bash', [CLI_PATH], {env, input: 'from Bash'});
      assertSuccess(bashArmor, 'Bash encrypt');
      const fingerprint = run('ssh-keygen', ['-lf', beta.publicKey]).stdout.split(/\s+/)[1];
      assert.ok(jsArmor.startsWith(`ssh-agent-crypt:v2:${fingerprint}.`));
      assert.ok(bashArmor.stdout.startsWith(`ssh-agent-crypt:v2:${fingerprint}.`));
      assertSuccess(run('ssh-add', ['-D'], {env}), 'remove identities');
      addKey(env, alpha.privateKey);
      addKey(env, beta.privateKey);
      assert.equal(await decrypt(bashArmor.stdout, undefined, {env}), 'from Bash');
      const decoded = run('bash', [CLI_PATH, '-decrypt'], {env, input: jsArmor});
      assertSuccess(decoded, 'Bash decrypt reordered keys');
      assert.equal(decoded.stdout, 'from JS');
      assert.equal(await decrypt(jsArmor, undefined, {env}), 'from JS');
      // The fingerprint must be authenticated even with an explicit selector.
      const other = run('ssh-keygen', ['-lf', alpha.publicKey]).stdout.split(/\s+/)[1];
      const tampered = jsArmor.replace(fingerprint, other);
      await assert.rejects(() => decrypt(tampered, beta.comment, {env}), /Authentication failed/);
      const rejected = run('bash', [CLI_PATH, '-decrypt', beta.comment], {env, input: tampered});
      assert.notEqual(rejected.status, 0);
      assert.match(rejected.stderr, /Authentication failed/);
      assertSuccess(run('ssh-add', ['-d', beta.privateKey], {env}), 'remove selected key');
      await assert.rejects(() => decrypt(jsArmor, undefined, {env}), /Key not found/);
      const missing = run('bash', [CLI_PATH, '-decrypt'], {env, input: jsArmor});
      assert.notEqual(missing.status, 0);
      assert.match(missing.stderr, /Key not found/);
    });
  });
}

for(const type of ['ed25519', 'rsa']) {
  test(`v1 remains readable without changing the v2 encryption flow (${type})`, async () => {
    const {decrypt} = require('..');
    await withAgent(async ({tmpDir, env}) => {
      const key = createKey(tmpDir, 'legacy@test', type);
      addKey(env, key.privateKey);
      const encrypted = run('bash', [CLI_PATH], {env, input: 'legacy token'});
      assertSuccess(encrypted, 'Bash encryption');
      const [, salt, iv, ciphertext] = encrypted.stdout.trim().slice('ssh-agent-crypt:v2:'.length).split('.');
      const signed = run('ssh-keygen', ['-Y', 'sign', '-f', key.privateKey, '-n', 'file'], {env, input: salt});
      assertSuccess(signed, 'sign legacy salt');
      const {createHash, createHmac} = require('crypto');
      const signature = signed.stdout.split('\n').filter(line => line && !line.startsWith('-----')).join('');
      const material = createHash('sha512').update(Buffer.from(signature, 'base64')).digest('hex');
      const macKey = createHash('sha256').update('mac:' + material).digest();
      const payload = `${salt}.${iv}.${ciphertext}`;
      const mac = createHmac('sha256', macKey).update(payload).digest('hex');
      const armored = {stdout: `ssh-agent-crypt:v1:${payload}.${mac}\n`};
      assert.match(armored.stdout, /^ssh-agent-crypt:v1:/);
      assert.equal(await decrypt(armored.stdout, undefined, {env}), 'legacy token');
      assert.equal(await decrypt(armored.stdout, key.comment, {env}), 'legacy token');
      const decoded = run('bash', [CLI_PATH, '-decrypt'], {env, input: armored.stdout});
      assertSuccess(decoded, 'Bash reads original v1');
      assert.equal(decoded.stdout, 'legacy token');
    });
  });
}

test('Bash signing failures abort encryption and decryption without output', async () => {
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'failure@test');
    addKey(env, key.privateKey);
    const armored = run('bash', [CLI_PATH], {env, input: 'secret'});
    assertSuccess(armored, 'prepare ciphertext');
    const realKeygen = run('which', ['ssh-keygen']).stdout.trim();
    const mockDirectory = path.join(tmpDir, 'mock-bin');
    fs.mkdirSync(mockDirectory);
    fs.writeFileSync(path.join(mockDirectory, 'ssh-keygen'), `#!/usr/bin/env bash
if [ "$1" = '-Y' ]; then
  echo 'Agent refused signature' >&2
  exit 1
fi
exec '${realKeygen}' "$@"
`, {mode: 0o700});
    const failing = {...env, PATH: `${mockDirectory}:${env.PATH}`};
    for(const [args, input] of [[[], 'secret'], [['-decrypt'], armored.stdout]]) {
      const result = run('bash', [CLI_PATH, ...args], {env: failing, input});
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /Unable to derive/);
    }
  });
});

test('Bash unavailable agent fails without emitting ciphertext', () => {
  const result = run('bash', [CLI_PATH], {
    env: {...process.env, SSH_AUTH_SOCK: '/nonexistent/agent.sock'}, input: 'secret',
  });
  assert.notEqual(result.status, 0);
  assert.equal(result.stdout, '');
  assert.match(result.stderr, /Unable to list ssh-agent keys/);
});

test('Bash encryption waits for upstream EOF before contacting the agent', async () => {
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'pipeline@test');
    addKey(env, key.privateKey);
    const realAdd = run('which', ['ssh-add']).stdout.trim();
    const mockDirectory = path.join(tmpDir, 'mock-bin');
    const marker = path.join(tmpDir, 'agent-contacted');
    fs.mkdirSync(mockDirectory);
    fs.writeFileSync(path.join(mockDirectory, 'ssh-add'), `#!/usr/bin/env bash
: > "$MARKER"
exec '${realAdd}' "$@"
`, {mode: 0o700});
    const result = run('bash', ['-o', 'pipefail', '-c', `
      { sleep 0.1; test ! -f "$MARKER" || exit 1; printf 'pipeline input\\n\\n'; } |
      bash "$CLI"
    `], {env: {...env, PATH: `${mockDirectory}:${env.PATH}`, MARKER: marker, CLI: CLI_PATH}});
    assertSuccess(result, 'wait for producer');
    assert.ok(fs.existsSync(marker));
    const {decrypt} = require('..');
    assert.equal(await decrypt(result.stdout, undefined, {env}), 'pipeline input\n\n');
  });
});

test('Bash decrypt/encrypt pipeline preserves binary input and trailing newlines', async () => {
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'binary@test');
    addKey(env, key.privateKey);
    const input = Buffer.from([0, 255, 128, 65, 10, 10]);
    const armored = run('bash', [CLI_PATH], {env, input});
    assertSuccess(armored, 'encrypt binary');
    const pipeline = run('bash', ['-o', 'pipefail', '-c', 'bash "$CLI" -decrypt | bash "$CLI"'], {
      env: {...env, CLI: CLI_PATH}, input: armored.stdout,
    });
    assertSuccess(pipeline, 'rearmor binary');
    const decoded = run('bash', [CLI_PATH, '-decrypt'], {env, input: pipeline.stdout, encoding: null});
    assert.equal(decoded.status, 0);
    assert.deepEqual(decoded.stdout, input);
  });
});
