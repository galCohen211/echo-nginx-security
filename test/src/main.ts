// Compatibility test: echo-nginx:1.25.5 must answer exactly like nginx:1.25-bookworm.
//
//   node dist/main.js            (after `npm run build`; `make test` does both)
//
// Exit code 0 = all scenarios identical, 1 = differences or failures, 2 = setup error.
import { compareExchanges, NORMALIZED_HEADERS } from "./compare.js";
import {
  containerLogs, ensureImage, removeContainers, startContainer, waitReady,
  type Container, type Target,
} from "./docker.js";
import { prepareFixtures } from "./fixtures.js";
import { rawExchange, type ExchangeResult } from "./http.js";
import { CVE_2024_7347, CVE_2024_7347_LOG, SCENARIOS, type Scenario } from "./scenarios.js";

const UPSTREAM: Target = { label: "upstream", image: process.env.UPSTREAM_IMAGE ?? "nginx:1.25-bookworm" };
const CANDIDATE: Target = { label: "echo", image: process.env.CANDIDATE_IMAGE ?? "echo-nginx:1.25.5" };

const running: Container[] = [];
let cleaning: Promise<void> | undefined;
const cleanup = () => (cleaning ??= removeContainers(running));

for (const sig of ["SIGINT", "SIGTERM"] as const) {
  process.on(sig, () => {
    console.error(`\n${sig} received, removing containers...`);
    void cleanup().finally(() => process.exit(130));
  });
}

function checkNode(): void {
  const major = Number(process.versions.node.split(".")[0]);
  if (major < 20) {
    console.error(`Node.js 20 or newer is required (found ${process.version}).`);
    process.exit(2);
  }
}

function exchange(c: Container, s: Scenario): Promise<ExchangeResult> {
  return rawExchange(s.port === "default" ? c.ports.default : c.ports.custom, s.send, { head: s.head, timeoutMs: 15_000 });
}

function statuses(r: ExchangeResult): string {
  return r.responses.map((x) => x.status).join(",") || "none";
}

async function main(): Promise<number> {
  checkNode();
  const fixtures = prepareFixtures();
  await Promise.all([ensureImage(UPSTREAM.image), ensureImage(CANDIDATE.image)]);

  for (const t of [UPSTREAM, CANDIDATE]) running.push(await startContainer(t, fixtures));
  const [up, cand] = running;
  await Promise.all(running.map((c) => waitReady(c)));
  console.log(`upstream  ${up.image.padEnd(22)} ports 80->${up.ports.default} 8080->${up.ports.custom}`);
  console.log(`candidate ${cand.image.padEnd(22)} ports 80->${cand.ports.default} 8080->${cand.ports.custom}`);
  console.log(`normalized headers: ${NORMALIZED_HEADERS.map((h) => `${h.header} (${h.rule})`).join("; ")}\n`);

  let failed = 0;
  for (const s of SCENARIOS) {
    const [a, b] = await Promise.all([exchange(up, s), exchange(cand, s)]);
    const problems = compareExchanges(a, b, [up.label, cand.label], { tolerateSocketError: s.tolerateSocketError });
    const got = a.responses.map((r) => r.status);
    if (got.join(",") !== s.expect.join(",")) {
      problems.push(`unexpected status from ${up.label}: got ${statuses(a)}, scenario expects ${s.expect.join(",")}`);
    }
    const ok = problems.length === 0;
    if (!ok) failed++;
    console.log(`${ok ? "PASS" : "FAIL"}  ${s.id.padEnd(26)} ${s.title}  [${statuses(a)} | ${statuses(b)}]`);
    for (const p of problems) console.log(`      ${p.replace(/\n/g, "\n      ")}`);
  }

  // Backport check: expected to differ from upstream.
  console.log(`\nBackport check (expected to differ from upstream, not counted as a compatibility failure):`);
  const s = CVE_2024_7347;
  const [a, b] = await Promise.all([exchange(up, s), exchange(cand, s)]);
  const [upLogs, candLogs] = await Promise.all([containerLogs(up), containerLogs(cand)]);
  const candLogged = candLogs.includes(CVE_2024_7347_LOG);
  const upLogged = upLogs.includes(CVE_2024_7347_LOG);
  const describe = (r: ExchangeResult) =>
    r.responses.length ? `${r.responses[0].statusLine}, body ${r.responses[0].body.length} B` : `no response (${r.socketError ?? (r.timedOut ? "timeout" : "closed")})`;
  console.log(`      ${up.label.padEnd(9)}: ${describe(a)}; error log mentions "${CVE_2024_7347_LOG}": ${upLogged}`);
  console.log(`      ${cand.label.padEnd(9)}: ${describe(b)}; error log mentions "${CVE_2024_7347_LOG}": ${candLogged}`);
  const backportOk = b.responses[0]?.status === 500 && candLogged;
  console.log(`${backportOk ? "PASS" : "FAIL"}  ${s.id.padEnd(26)} patched image rejects the file with 500 and logs the check`);
  if (!backportOk) failed++;

  const total = SCENARIOS.length + 1;
  console.log(`\n${total - failed}/${total} checks passed.`);
  return failed === 0 ? 0 : 1;
}

main()
  .then(async (code) => {
    await cleanup();
    process.exitCode = code;
  })
  .catch(async (err: unknown) => {
    console.error(`\nERROR: ${err instanceof Error ? err.message : String(err)}`);
    await cleanup();
    process.exitCode = 2;
  });
