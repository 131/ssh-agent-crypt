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
  // Git does not keep 0600; ssh-add refuses "too open" keys, so load a private copy.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ssh-agent-crypt-key-"));
  const copy = path.join(dir, path.basename(keyPath));
  fs.copyFileSync(keyPath, copy);
  fs.chmodSync(copy, 0o600);
  try {
    const result = run("ssh-add", [copy], {env});
    assertSuccess(result, "ssh-add " + keyPath);
  } finally {
    fs.rmSync(dir, {recursive: true, force: true});
  }
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
  // Tests pick keys explicitly or expect the first agent key: scrub the
  // default-key variables a developer shell may carry.
  const env = startAgent({...process.env, SSH_AGENT_CRYPT_KEY: "", VAUTH_USER_IDENTITY: "", VAUTH_USER_MAIL: ""});

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
    assert.match(lines[0], /^ssh-agent-crypt:v3:SHA256:[A-Za-z0-9+/]{43}\.[A-Za-z0-9+/=]+\.[0-9a-f]+\.[A-Za-z0-9+/=]+\.[0-9a-f]+$/);

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
    assert.match(armored, /^ssh-agent-crypt:v3:/);
    assert.equal((await decrypt(armored, "node@test", {env})).toString(), plaintext);
    const decrypted = run("bash", [CLI_PATH, "-decrypt", "node@test"], {env, input: armored});
    assertSuccess(decrypted, "CLI decrypts Node armor");
    assert.equal(decrypted.stdout, plaintext);
    const encrypted = run("bash", [CLI_PATH, "node@test"], {env, input: plaintext});
    assertSuccess(encrypted, "CLI encrypts for Node");
    assert.equal((await decrypt(encrypted.stdout, "node@test", {env})).toString(), plaintext);
    await assert.rejects(() => decrypt(armored.replace(/.$/m, "x"), "node@test", {env}), /Authentication failed/);
    await assert.rejects(() => encrypt(plaintext, "missing@test", {env}), /Key not found/);
  });
});

test("Node CLI (npm bin) interoperates with Bash and matches its interface", async () => {
  const NODE_CLI = path.join(REPO_ROOT, "bin", "ssh-agent-crypt.js");
  const {decrypt} = require("..");
  await withAgent(async ({tmpDir, env}) => {
    addKey(env, createKey(tmpDir, "nodecli@test").privateKey);
    const payload = Buffer.from("node cli\n\x00\xff binary tail");
    const armored = run(process.execPath, [NODE_CLI, "nodecli@test"], {env, input: payload, encoding: null});
    assertSuccess(armored, "Node CLI encrypts");
    assert.match(armored.stdout.toString(), /^ssh-agent-crypt:v3:/);
    const fromBash = run("bash", [CLI_PATH, "-decrypt", "nodecli@test"], {env, input: armored.stdout, encoding: null});
    assertSuccess(fromBash, "Bash decrypts Node CLI armor");
    assert.deepEqual(fromBash.stdout, payload);
    const bashArmor = run("bash", [CLI_PATH, "nodecli@test"], {env, input: payload, encoding: null});
    const fromNode = run(process.execPath, [NODE_CLI, "-decrypt"], {env, input: bashArmor.stdout, encoding: null});
    assertSuccess(fromNode, "Node CLI decrypts Bash armor");
    assert.deepEqual(fromNode.stdout, payload);
    assert.deepEqual(await decrypt(armored.stdout, undefined, {env}), payload);
    for(const args of [["-x"], ["a", "b"], ["-decrypt", "a", "b"]]) {
      const bad = run(process.execPath, [NODE_CLI, ...args], {env, input: ""});
      assert.equal(bad.status, 1, `usage for ${args.join(" ")}`);
      assert.match(bad.stderr, /^Usage:/);
    }
    const tampered = run(process.execPath, [NODE_CLI, "-decrypt"], {env, input: armored.stdout.toString().replace(/(.)\n$/, (m, c) => (c === "0" ? "1" : "0") + "\n")});
    assert.equal(tampered.status, 1);
    assert.match(tampered.stderr, /Authentication failed/);
    assert.equal(JSON.parse(fs.readFileSync(path.join(REPO_ROOT, "package.json"))).bin["ssh-agent-crypt"], "./bin/ssh-agent-crypt.js");
  });
});

test("SSH_AGENT_CRYPT_KEY stands in for the key argument, embedded fingerprints win", async () => {
  const NODE_CLI = path.join(REPO_ROOT, "bin", "ssh-agent-crypt.js");
  const {encrypt, decrypt} = require("..");
  const fixtures = path.join(REPO_ROOT, "test", "fixtures");
  await withAgent(async ({tmpDir, env: base}) => {
    const first = createKey(tmpDir, "first@test");
    const preferred = createKey(tmpDir, "preferred@test");
    addKey(base, first.privateKey);
    addKey(base, preferred.privateKey);
    addKey(base, path.join(fixtures, "ed25519"));
    const fp = comment => run("ssh-keygen", ["-lf", comment === "first@test" ? first.publicKey : preferred.publicKey]).stdout.split(" ")[1];
    const env = {...base, SSH_AGENT_CRYPT_KEY: "preferred@test"};
    const goBinary = run("bash", ["-c", "command -v go"]).status === 0 ? path.join(tmpDir, "ssh-agent-crypt-go") : null;
    if(goBinary)
      assertSuccess(run("go", ["build", "-o", goBinary, "./cmd/ssh-agent-crypt"], {cwd: REPO_ROOT, env}), "go build");
    const writers = {
      api: (input, key, e) => encrypt(input, key, {env: e}),
      bash: (input, key, e) => run("bash", [CLI_PATH, ...(key ? [key] : [])], {env: e, input}).stdout,
      node: (input, key, e) => run(process.execPath, [NODE_CLI, ...(key ? [key] : [])], {env: e, input}).stdout,
      ...(goBinary ? {go: (input, key, e) => run(goBinary, [...(key ? [key] : [])], {env: e, input}).stdout} : {}),
    };
    const readers = {
      api: async (armor, key, e) => (await decrypt(armor, key, {env: e})).toString(),
      bash: (armor, key, e) => run("bash", [CLI_PATH, "-decrypt", ...(key ? [key] : [])], {env: e, input: armor}).stdout,
      node: (armor, key, e) => run(process.execPath, [NODE_CLI, "-decrypt", ...(key ? [key] : [])], {env: e, input: armor}).stdout,
      ...(goBinary ? {go: (armor, key, e) => run(goBinary, ["-decrypt", ...(key ? [key] : [])], {env: e, input: armor}).stdout} : {}),
    };
    for(const [name, write] of Object.entries(writers)) {
      // No argument: env picks the key; without env, the first agent key.
      assert.ok((await write("x", undefined, env)).includes(fp("preferred@test")), `${name}: env key`);
      assert.ok((await write("x", undefined, base)).includes(fp("first@test")), `${name}: first key`);
      // Explicit argument beats env.
      assert.ok((await write("x", "first@test", env)).includes(fp("first@test")), `${name}: argument wins`);
    }
    const toFirst = await encrypt("for first", "first@test", {env: base});
    const v1 = fs.readFileSync(path.join(fixtures, "v1.ed25519.txt"), "utf8");
    for(const [name, read] of Object.entries(readers)) {
      // v3 addressed to another key still decrypts with env set: embedded fingerprint wins.
      assert.equal(await read(toFirst, undefined, env), "for first", `${name}: fingerprint wins over env`);
      // v1 has no fingerprint: env selects the key (the fixture key here).
      assert.equal(await read(v1, undefined, {...base, SSH_AGENT_CRYPT_KEY: "fixture-ed25519@test"}), "legacy token", `${name}: v1 via env`);
    }
    // Fallback order: SSH_AGENT_CRYPT_KEY, VAUTH_USER_IDENTITY, VAUTH_USER_MAIL.
    for(const [name, write] of Object.entries(writers)) {
      const vauth = {...base, VAUTH_USER_MAIL: "preferred@test"};
      assert.ok((await write("x", undefined, vauth)).includes(fp("preferred@test")), `${name}: VAUTH_USER_MAIL`);
      assert.ok((await write("x", undefined, {...vauth, VAUTH_USER_IDENTITY: "first@test"})).includes(fp("first@test")), `${name}: VAUTH_USER_IDENTITY beats MAIL`);
      assert.ok((await write("x", undefined, {...vauth, VAUTH_USER_IDENTITY: "first@test", SSH_AGENT_CRYPT_KEY: "preferred@test"})).includes(fp("preferred@test")), `${name}: SSH_AGENT_CRYPT_KEY beats VAUTH`);
    }
    const missing = run("bash", [CLI_PATH], {env: {...base, SSH_AGENT_CRYPT_KEY: "nobody@test"}, input: "x"});
    assert.equal(missing.status, 1);
    assert.match(missing.stderr, /Key not found: nobody@test/);
    await assert.rejects(() => encrypt("x", undefined, {env: {...base, SSH_AGENT_CRYPT_KEY: "nobody@test"}}), /Key not found: nobody@test/);
  });
});

test("Node API round-trips binary payloads with Go and Bash", async () => {
  const {encrypt, decrypt} = require("..");
  await withAgent(async ({tmpDir, env}) => {
    addKey(env, createKey(tmpDir, "binary@test").privateKey);
    const payload = Buffer.from([0x00, 0xff, 0xfe, 0x80, 0xc3, 0x28, 0x0a, 0x0d, 0x00, 0x9f]);
    const armored = await encrypt(payload, "binary@test", {env});
    assert.deepEqual(await decrypt(armored, "binary@test", {env}), payload);
    const fromBash = run("bash", [CLI_PATH, "-decrypt", "binary@test"], {env, input: armored, encoding: null});
    assertSuccess(fromBash, "Bash decrypts binary Node armor");
    assert.deepEqual(fromBash.stdout, payload);
    const toNode = run("bash", [CLI_PATH, "binary@test"], {env, input: payload, encoding: null});
    assertSuccess(toNode, "Bash encrypts binary for Node");
    assert.deepEqual(await decrypt(toNode.stdout, "binary@test", {env}), payload);
    if(run("bash", ["-c", "command -v go"]).status === 0) {
      const goBinary = path.join(tmpDir, "ssh-agent-crypt-go");
      assertSuccess(run("go", ["build", "-o", goBinary, "./cmd/ssh-agent-crypt"], {cwd: REPO_ROOT, env}), "go build");
      const fromGo = run(goBinary, ["-decrypt", "binary@test"], {env, input: armored, encoding: null});
      assertSuccess(fromGo, "Go decrypts binary Node armor");
      assert.deepEqual(fromGo.stdout, payload);
    }
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
        assert.equal((await decrypt(encrypted.stdout, selector, {env})).toString(), plaintext);
      }
      const empty = await encrypt('', undefined, {env});
      assert.equal((await decrypt(empty, undefined, {env})).toString(), '');
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
    assert.equal((await decrypt(encrypted.stdout, key.privateKey, {env})).toString(), 'reverse');
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
  await assert.rejects(() => decrypt('ssh-agent-crypt:v3:missing.parts'), /Invalid key fingerprint/);
});


test('JS encryption and decryption work with no executables on PATH', async () => {
  const {encrypt, decrypt} = require('..');
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'pure-js@test');
    addKey(env, key.privateKey);
    const options = {env: {...env, PATH: tmpDir}};
    const armor = await encrypt('no subprocess', undefined, options);
    assert.equal((await decrypt(armor, undefined, options)).toString(), 'no subprocess');
  });
});

for(const type of ['ed25519', 'rsa']) {
  test(`v3 selects the embedded fingerprint after agent key reordering (${type})`, async () => {
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
      assert.ok(jsArmor.startsWith(`ssh-agent-crypt:v3:${fingerprint}.`));
      assert.ok(bashArmor.stdout.startsWith(`ssh-agent-crypt:v3:${fingerprint}.`));
      assertSuccess(run('ssh-add', ['-D'], {env}), 'remove identities');
      addKey(env, alpha.privateKey);
      addKey(env, beta.privateKey);
      assert.equal((await decrypt(bashArmor.stdout, undefined, {env})).toString(), 'from Bash');
      const decoded = run('bash', [CLI_PATH, '-decrypt'], {env, input: jsArmor});
      assertSuccess(decoded, 'Bash decrypt reordered keys');
      assert.equal(decoded.stdout, 'from JS');
      assert.equal((await decrypt(jsArmor, undefined, {env})).toString(), 'from JS');
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
  test(`fixtures: v1, v2 and v3 armors stay readable, relabeled headers fail (${type})`, async () => {
    const {decrypt} = require('..');
    const fixtures = path.join(REPO_ROOT, 'test', 'fixtures');
    const key = path.join(fixtures, type);
    await withAgent(async ({tmpDir, env}) => {
      addKey(env, createKey(tmpDir, 'alpha@test').privateKey);
      addKey(env, key);
      for(const version of ['v1', 'v2', 'v3']) {
        const armored = fs.readFileSync(path.join(fixtures, `${version}.${type}.txt`), 'utf8');
        assert.ok(armored.startsWith(`ssh-agent-crypt:${version}:`));
        const selectors = [key, `fixture-${type}@test`, ...(version === 'v1' ? [] : [undefined])];
        for(const selector of selectors) {
          assert.equal((await decrypt(armored, selector, {env})).toString(), 'legacy token', `${version} node ${selector}`);
          const bash = run('bash', [CLI_PATH, '-decrypt', ...(selector ? [selector] : [])], {env, input: armored});
          assertSuccess(bash, `${version} bash ${selector}`);
          assert.equal(bash.stdout, 'legacy token');
        }
        if(version === 'v1')
          continue;
        const other = version === 'v2' ? 'v3' : 'v2';
        const relabeled = armored.replace(`ssh-agent-crypt:${version}:`, `ssh-agent-crypt:${other}:`);
        await assert.rejects(() => decrypt(relabeled, undefined, {env}), /Authentication failed/);
        const bash = run('bash', [CLI_PATH, '-decrypt'], {env, input: relabeled});
        assert.notEqual(bash.status, 0);
        assert.match(bash.stderr, /Authentication failed/);
      }
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
    assert.equal((await decrypt(result.stdout, undefined, {env})).toString(), 'pipeline input\n\n');
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

const GO_AVAILABLE = run("bash", ["-c", "command -v go"]).status === 0;

test('Go CLI interoperates with Bash and Node', {skip: !GO_AVAILABLE && 'go not available'}, async () => {
  const {encrypt, decrypt} = require('..');
  await withAgent(async ({tmpDir, env}) => {
    const goBinary = path.join(tmpDir, 'ssh-agent-crypt-go');
    assertSuccess(run('go', ['build', '-o', goBinary, './cmd/ssh-agent-crypt'], {cwd: REPO_ROOT, env}), 'go build');
    for(const type of ['ed25519', 'rsa']) {
      const key = createKey(tmpDir, `go-${type}@test`, type);
      addKey(env, key.privateKey);
      const plaintext = `Go ${type}: coucou bibou 🐻\n`;
      const goArmor = run(goBinary, [key.comment], {env, input: plaintext});
      assertSuccess(goArmor, 'Go encrypts');
      assert.match(goArmor.stdout, /^ssh-agent-crypt:v3:SHA256:/);
      const bash = run('bash', [CLI_PATH, '-decrypt'], {env, input: goArmor.stdout});
      assertSuccess(bash, 'Bash decrypts Go');
      assert.equal(bash.stdout, plaintext);
      assert.equal((await decrypt(goArmor.stdout, undefined, {env})).toString(), plaintext);
      const bashArmor = run('bash', [CLI_PATH, key.comment], {env, input: plaintext});
      assertSuccess(bashArmor, 'Bash encrypts');
      const goFromBash = run(goBinary, ['-decrypt'], {env, input: bashArmor.stdout});
      assertSuccess(goFromBash, 'Go decrypts Bash');
      assert.equal(goFromBash.stdout, plaintext);
      const goFromNode = run(goBinary, ['-decrypt'], {env, input: await encrypt(plaintext, key.comment, {env})});
      assertSuccess(goFromNode, 'Go decrypts Node');
      assert.equal(goFromNode.stdout, plaintext);
    }
    const tampered = run(goBinary, ['-decrypt'], {env, input: 'ssh-agent-crypt:v3:SHA256:' + 'A'.repeat(43) + '.c2FsdA==.00.AA==.00\n'});
    assert.notEqual(tampered.status, 0);
    assert.equal(tampered.stdout, '');
  });
});

for(const agentAvailable of [true, false]) {
  test(`Bash rejects ECDSA key files ${agentAvailable ? 'with' : 'without'} an agent`, async () => {
    await withAgent(async ({tmpDir, env}) => {
      const key = createKey(tmpDir, 'ecdsa-file@test', 'ecdsa');
      addKey(env, key.privateKey);
      const selectedEnv = {...env};
      if(!agentAvailable) {
        delete selectedEnv.SSH_AUTH_SOCK;
        delete selectedEnv.SSH_AGENT_PID;
      }
      for(const selector of [key.privateKey, key.publicKey]) {
        const result = run('bash', [CLI_PATH, selector], {env: selectedEnv, input: 'must not encrypt'});
        assert.notEqual(result.status, 0);
        assert.equal(result.stdout, '');
        assert.match(result.stderr, /Unsupported key type: ecdsa-sha2-/);
      }
    });
  });
}

test('Bash public key files require the agent, even beside a private key', async () => {
  await withAgent(async ({tmpDir, env}) => {
    const key = createKey(tmpDir, 'public-only@test');
    addKey(env, key.privateKey);
    const armored = run('bash', [CLI_PATH, key.publicKey], {env, input: 'agent-backed'});
    assertSuccess(armored, 'public key with agent');
    const plaintext = run('bash', [CLI_PATH, '-decrypt', key.publicKey], {env, input: armored.stdout});
    assertSuccess(plaintext, 'decrypt with public key');
    assert.equal(plaintext.stdout, 'agent-backed');
    assertSuccess(run('ssh-add', ['-d', key.privateKey], {env}), 'remove private key from agent');
    for(const selectedEnv of [env, {...env, SSH_AUTH_SOCK: ''}]) {
      const result = run('bash', [CLI_PATH, key.publicKey], {env: selectedEnv, input: 'must not encrypt'});
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /Unable to derive/);
    }
  });
});

test('fixed fixtures pin legacy readers and exact Bash/Node v3 writers', async () => {
  const {decrypt} = require('..');
  await withAgent(async ({tmpDir, env}) => {
    const fixtureDir = path.join(__dirname, 'fixtures');
    const realOpenSSL = run('which', ['openssl']).stdout.trim();
    const mockDir = path.join(tmpDir, 'mock-bin');
    fs.mkdirSync(mockDir);
    // Only replace entropy for this known-answer test, never production code.
    fs.writeFileSync(path.join(mockDir, 'openssl'), `#!/usr/bin/env bash
if [ "$*" = 'rand -base64 32' ]; then printf '%s\\n' "$FIXTURE_SALT"; exit; fi
if [ "$*" = 'rand -hex 16' ]; then printf '%s\\n' "$FIXTURE_IV"; exit; fi
exec '${realOpenSSL}' "$@"
`, {mode: 0o700});
    for(const type of ['ed25519', 'rsa']) {
      const key = path.join(fixtureDir, type);
      addKey(env, key);
      for(const version of ['v1', 'v2', 'v3']) {
        const armor = fs.readFileSync(path.join(fixtureDir, `${version}.${type}.txt`), 'utf8');
        for(const selector of [key, key + '.pub', `fixture-${type}@test`, ...(version === 'v1' ? [] : [undefined])]) {
          const result = run('bash', [CLI_PATH, '-decrypt', ...(selector ? [selector] : [])], {env, input: armor});
          assertSuccess(result, `Bash ${version} ${type}`);
          assert.equal(result.stdout, 'legacy token');
          assert.equal((await decrypt(armor, selector, {env})).toString(), 'legacy token');
        }
        // Neither a changed header nor a malformed MAC may be accepted.
        const mutations = [armor.trimEnd() + 'zz\n'];
        if(version === 'v3') {
          const fields = armor.trimEnd().slice('ssh-agent-crypt:v3:'.length).split('.');
          for(let i = 0; i < fields.length; ++i) {
            const changed = [...fields];
            if(i === 0)
              changed[i] = 'SHA256:' + 'A'.repeat(43);
            else
              changed[i] = (changed[i][0] === 'a' ? 'b' : 'a') + changed[i].slice(1);
            mutations.push('ssh-agent-crypt:v3:' + changed.join('.') + '\n');
          }
        }
        if(version !== 'v1')
          mutations.push(armor.replace(`:${version}:`, version === 'v3' ? ':v2:' : ':v3:'));
        for(const input of mutations) {
          const result = run('bash', [CLI_PATH, '-decrypt', key], {env, input});
          assert.notEqual(result.status, 0);
          assert.equal(result.stdout, '');
          await assert.rejects(decrypt(input, key, {env}), /Authentication failed/);
        }
        if(version !== 'v3')
          continue;
        const fields = armor.trimEnd().slice('ssh-agent-crypt:v3:'.length).split('.');
        const fixedEnv = {...env, PATH: `${mockDir}:${env.PATH}`, FIXTURE_SALT: fields[1], FIXTURE_IV: fields[2]};
        const bash = run('bash', [CLI_PATH, key], {env: fixedEnv, input: 'legacy token'});
        assertSuccess(bash, 'fixed Bash writer');
        assert.equal(bash.stdout, armor);
        // A fresh process loads encrypt after injecting the fixed random bytes.
        const script = `
          const crypto = require('crypto');
          const entropy = [Buffer.from(process.env.FIXTURE_SALT, 'base64'), Buffer.from(process.env.FIXTURE_IV, 'hex')];
          crypto.randomBytes = size => {
            const bytes = entropy.shift();
            if(!bytes || bytes.length !== size) throw new Error('Unexpected entropy request');
            return bytes;
          };
          require(process.argv[1]).encrypt('legacy token', process.argv[2]).then(out => process.stdout.write(out));
        `;
        const node = run('node', ['-e', script, REPO_ROOT, key], {env: fixedEnv});
        assertSuccess(node, 'fixed Node writer');
        assert.equal(node.stdout, armor);
      }
    }
  });
});

test('Bash keeps encrypted private key files usable through the agent', async () => {
  await withAgent(async ({tmpDir, env}) => {
    for(const type of ['ed25519', 'rsa', 'ecdsa']) {
      const key = createKey(tmpDir, `encrypted-${type}@test`, type);
      addKey(env, key.privateKey);
      assertSuccess(run('ssh-keygen', ['-q', '-p', '-P', '', '-N', 'test-only-passphrase', '-f', key.privateKey]), 'encrypt private key');
      const encrypted = run('bash', [CLI_PATH, key.privateKey], {env, input: 'agent-unlocked'});
      if(type === 'ecdsa') {
        assert.notEqual(encrypted.status, 0);
        assert.equal(encrypted.stdout, '');
        assert.match(encrypted.stderr, /Unsupported key type: ecdsa-sha2-/);
      } else {
        assertSuccess(encrypted, 'sign encrypted private file through agent');
        const decoded = run('bash', [CLI_PATH, '-decrypt', key.privateKey], {env, input: encrypted.stdout});
        assertSuccess(decoded, 'decrypt with encrypted private file');
        assert.equal(decoded.stdout, 'agent-unlocked');
      }
    }
  });
});

test('Bash inspects and signs the private file, not a stale public sibling', async () => {
  await withAgent(async ({tmpDir, env}) => {
    const ec = createKey(tmpDir, 'stale-ec@test', 'ecdsa');
    const rsa = createKey(tmpDir, 'stale-rsa@test', 'rsa');
    const ed = createKey(tmpDir, 'stale-ed@test', 'ed25519');
    for(const key of [ec, rsa, ed])
      addKey(env, key.privateKey);
    const rsaFingerprint = run('ssh-keygen', ['-lf', rsa.publicKey]).stdout.trim().split(/\s+/)[1];
    fs.copyFileSync(rsa.publicKey, ec.publicKey);
    fs.copyFileSync(ed.publicKey, rsa.publicKey);
    for(const selectedEnv of [env, {...env, SSH_AUTH_SOCK: ''}]) {
      const rejected = run('bash', [CLI_PATH, ec.privateKey], {env: selectedEnv, input: 'must reject'});
      assert.notEqual(rejected.status, 0);
      assert.equal(rejected.stdout, '');
      assert.match(rejected.stderr, /Unsupported key type: ecdsa-sha2-/);
    }
    const encrypted = run('bash', [CLI_PATH, rsa.privateKey], {env, input: 'actual RSA key'});
    assertSuccess(encrypted, 'sign actual private file');
    assert.ok(encrypted.stdout.startsWith('ssh-agent-crypt:v3:' + rsaFingerprint + '.'));
    for(const selector of [undefined, rsa.privateKey]) {
      const decoded = run('bash', [CLI_PATH, '-decrypt', ...(selector ? [selector] : [])], {env, input: encrypted.stdout});
      assertSuccess(decoded, 'decrypt actual RSA key');
      assert.equal(decoded.stdout, 'actual RSA key');
    }
  });
});
