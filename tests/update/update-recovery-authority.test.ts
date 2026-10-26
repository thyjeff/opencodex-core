import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { repoPath } from "../helpers/repo-root";
import { createUpdateServiceHomePolicy, type UpdateServiceHomeAuthority } from "../../src/update/service-home-policy.mjs";

// Execute the production bodies with OS/process I/O injected, as in update-home-recovery.
function extract(file: string, start: string, end: string, invoke: string) {
  const source = readFileSync(repoPath(file), "utf8");
  const from = source.indexOf(start), to = source.indexOf(end, from);
  expect(from).toBeGreaterThan(0); expect(to).toBeGreaterThan(from);
  const code = new Bun.Transpiler({ loader: "ts" }).transformSync(source.slice(from, to));
  return new Function("deps", `with (deps) { ${code}; return ${invoke}; }`);
}
const ghost = extract("src/update/job.ts", "async function waitForGhostListenClear(", "function packageLauncherPath(", "waitForGhostListenClear");
const restart = extract("src/update/job.ts", "async function restartAfterUpdate(", "/** Compact listen-holder summary", "restartAfterUpdate");

for (const reclaimed of [false, true]) for (const changed of ["foreign", "unknown"] as const) {
  test(`ghost wait refuses ${changed} authority before TCP mutation (${reclaimed ? "pinned attempt" : "reclaim timeout"})`, async () => {
    let now = 0, drops = 0, waits = 0, starts = 0, prepares = 0;
    let home: UpdateServiceHomeAuthority = { kind: "absent" };
    const job: { status?: string; restarted?: boolean; error?: string } = {};
    const logs: string[] = [];
    const waitForGhost = ghost({
      process: { pid: 100, platform: "win32" }, Date: { now: () => now },
      isProcessAlive: () => false,
      dropWindowsTcpRowsForLocalPort: () => { drops++; return { accessDenied: 0 }; },
      strictRuntimePortAvailable: async () => false,
    });
    const run = restart({
      createUpdateServiceHomePolicy, inspectUpdateServiceHome: () => home,
      updateJob: (_job: object, state: object, log?: string) => { Object.assign(job, state); if (log) logs.push(log); },
      loadConfig: () => ({}), restartCommand: () => ({}), RESTART_PORT_RECLAIM_MS: 100,
      process: { pid: 100 }, waitForGhostListenClear: waitForGhost,
      formatPortHolders: () => "fixture holders",
    });
    const io = {
      serviceHomeAuthorityFn: () => home,
      packageLauncherPathFn: () => "fixture launcher", readPidFn: () => null,
      listListenPidsFn: () => [9999], verifyOcxFn: () => null, isAliveFn: () => false,
      waitForPort: async () => reclaimed, probeProxyIdentity: async () => null,
      probeProxy: async () => true, preparePortForPinnedStartFn: () => { prepares++; },
      spawnDetachedStartFn: () => { starts++; throw new Error("unauthorized spawn"); },
      sleepMs: async () => {
        waits++; now += waits === 1 ? 500 : 100_000;
        home = changed === "foreign" ? { kind: changed, subject: "a".repeat(64) } : { kind: changed };
      },
    };
    const result = await run(job, { port: 19001, hostname: "127.0.0.1" }, io).catch((error: unknown) => error);
    expect(drops).toBe(1); // The first drop was authorized; the next iteration must refuse.
    expect(result).toBe(false);
    expect(job).toMatchObject({ status: "failed", restarted: false });
    expect(job.error).toContain("ocx service status");
    expect(waits).toBe(1); expect(starts).toBe(0); expect(prepares).toBe(reclaimed ? 1 : 0);
    expect(logs.some(line => /did not clear|not bindable|access denied/.test(line))).toBe(false);
  });
}

for (const reclaimed of [false, true]) test(`ghost denial stays latched after a transient re-match (${reclaimed})`, async () => {
  let denied = false, checks = 0, prepares = 0;
  const job: { status?: string; error?: string } = {};
  const run = restart({
    createUpdateServiceHomePolicy, inspectUpdateServiceHome: () => ({ kind: "absent" }),
    updateJob: (_job: object, state: object) => Object.assign(job, state),
    loadConfig: () => ({}), restartCommand: () => ({}), RESTART_PORT_RECLAIM_MS: 100,
    process: { pid: 100 }, formatPortHolders: () => "fixture holders",
    waitForGhostListenClear: async (...args: unknown[]) => {
      // Re-match before the wait returns: only the gate's latch remembers the denial.
      const gate = args[6] as (() => boolean) | undefined;
      denied = true; const refused = gate?.() === false; denied = false;
      expect(refused).toBe(true);
      return { ok: false, accessDenied: false };
    },
  });
  expect(await run(job, { port: 19001, hostname: "127.0.0.1" }, {
    serviceHomeAuthorityFn: () => { checks++; return { kind: denied ? "unknown" : "absent" }; },
    packageLauncherPathFn: () => "fixture launcher", readPidFn: () => null,
    listListenPidsFn: () => [9999], verifyOcxFn: () => null, isAliveFn: () => false,
    waitForPort: async () => reclaimed, probeProxyIdentity: async () => null,
    spawnDetachedStartFn: () => { throw new Error("unauthorized spawn"); },
    preparePortForPinnedStartFn: () => { prepares++; }, sleepMs: async () => {},
  })).toBe(false);
  expect(job.status).toBe("failed"); expect(job.error).toContain("ocx service status");
  expect(checks).toBeGreaterThan(1); expect(prepares).toBe(reclaimed ? 1 : 0);
});

for (const lane of ["Bun", "Node"] as const) test(`${lane} direct recovery reports a retained lease without throwing or probing/spawning`, async () => {
  const direct = lane === "Bun"
    ? extract("src/update/index.ts", "  const startProxyDirectly = async", "  // #7043:", "startProxyDirectly")
    : extract("bin/ocx.mjs", "  function startProxyDirectly()", "  // #7043:", "startProxyDirectly");
  const warnings: string[] = [];
  let acquisitions = 0, probes = 0, spawns = 0;
  const acquire = () => {
    acquisitions++;
    throw Object.assign(new Error("OWNERSHIP_MUTATION_LEASE_BUSY private fixture details"), { code: "OWNERSHIP_MUTATION_LEASE_BUSY" });
  };
  const result = await direct({
    mutation: { reacquire: acquire }, reacquireUpdateLease: acquire,
    homePolicy: { check: () => { probes++; return true; } },
    readOwnership: () => { probes++; }, resolvedRuntimeOwnership: async () => { probes++; },
    spawn: () => { spawns++; }, console: { warn: (line: string) => warnings.push(line), error: (line: string) => warnings.push(line) },
  })();
  expect(result).toBe(false); expect(acquisitions).toBe(1); expect(probes).toBe(0); expect(spawns).toBe(0);
  expect(warnings).toHaveLength(1);
  expect(warnings[0]).toContain("ocx service repair"); expect(warnings[0]).toContain("ocx start");
  expect(warnings[0]).not.toContain("private fixture details"); expect(warnings[0]).not.toContain("OWNERSHIP_MUTATION_LEASE_BUSY");
});
