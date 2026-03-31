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
    assert.match(lines[0], /^ssh-agent-crypt:v1:[A-Za-z0-9+/=]+\.[0-9a-f]+\.[A-Za-z0-9+/=]+\.[0-9a-f]+$/);

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
