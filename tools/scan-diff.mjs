// Compares the baseline scan of nginx:1.25-bookworm with the scan of
// echo-nginx:1.25.5 and writes reports/diff.md.
//
//   node tools/scan-diff.mjs        (run from the repo root; `make scan` does this)
//
// Inputs:  reports/baseline-{trivy,grype}.json, reports/echo-{trivy,grype}.json
// Also queries both images with docker for their installed packages, and writes
// reports/{baseline,echo}-packages.txt as evidence for the attribution.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const ROOT = process.cwd();
const R = (f) => path.join(ROOT, "reports", f);
const UPSTREAM = "nginx:1.25-bookworm";
const ECHO = "echo-nginx:1.25.5";
const OPENSSL_PKGS = new Set(["libssl3", "openssl"]);
const MODULE_PKGS = ["nginx-module-geoip", "nginx-module-image-filter", "nginx-module-njs", "nginx-module-xslt"];
const WATCH = ["CVE-2024-6119", "CVE-2025-15467", "CVE-2024-7347"];
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Negligible", "Unknown"];

const docker = (...args) => execFileSync("docker", args, { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });

// --- package lists -------------------------------------------------------------
function packages(image) {
  const out = docker("run", "--rm", "--entrypoint", "dpkg-query", image, "-W", "-f", "${Package} ${Version}\\n");
  return new Map(out.trim().split("\n").map((l) => l.trim().split(" ")));
}
const pkgsBase = packages(UPSTREAM);
const pkgsEcho = packages(ECHO);
const dump = (m) => [...m].sort(([a], [b]) => a.localeCompare(b)).map(([p, v]) => `${p} ${v}`).join("\n") + "\n";
writeFileSync(R("baseline-packages.txt"), dump(pkgsBase));
writeFileSync(R("echo-packages.txt"), dump(pkgsEcho));

// Packages that exist upstream only because of the dynamic modules: what apt
// would remove together with the four module packages.
const moduleSet = new Set(
  docker("run", "--rm", "--entrypoint", "apt-get", UPSTREAM, "-s", "purge", "--auto-remove", ...MODULE_PKGS)
    .split("\n").map((l) => /^Purg (\S+)/.exec(l)?.[1]).filter(Boolean),
);

// --- findings ------------------------------------------------------------------
const sev = (s) => {
  const x = (s || "Unknown").toLowerCase();
  return x.charAt(0).toUpperCase() + x.slice(1);
};
function loadTrivy(file) {
  const j = JSON.parse(readFileSync(R(file), "utf8"));
  return (j.Results || []).flatMap((r) => r.Vulnerabilities || []).map((v) => ({
    id: v.VulnerabilityID, pkg: v.PkgName, version: v.InstalledVersion, severity: sev(v.Severity),
    fixed: v.FixedVersion || "", state: v.Status || "",
  }));
}
function loadGrype(file) {
  const j = JSON.parse(readFileSync(R(file), "utf8"));
  return (j.matches || []).map((m) => ({
    id: m.vulnerability.id, pkg: m.artifact.name, version: m.artifact.version, severity: sev(m.vulnerability.severity),
    fixed: (m.vulnerability.fix?.versions || []).join(", "), state: m.vulnerability.fix?.state || "",
  }));
}
const key = (f) => `${f.pkg} ${f.id}`;

function cause(f) {
  if (OPENSSL_PKGS.has(f.pkg)) return "openssl";
  if (!pkgsEcho.has(f.pkg)) return moduleSet.has(f.pkg) ? "modules" : "other";
  if (pkgsEcho.get(f.pkg) !== pkgsBase.get(f.pkg)) return "base";
  return "other";
}
const CAUSES = {
  openssl: "OpenSSL bump (libssl3/openssl 3.0.11-1~deb12u2 → 3.0.22-1~deb12u1)",
  modules: "Removed dynamic modules (package no longer installed)",
  base: "Newer Debian packages (base image refresh, Debian 12.5 → 12.15)",
  other: "Other",
};

function analyse(name, before, after) {
  const afterKeys = new Set(after.map(key));
  const beforeKeys = new Set(before.map(key));
  const removed = before.filter((f) => !afterKeys.has(key(f)));
  const still = after.filter((f) => beforeKeys.has(key(f)));
  const added = after.filter((f) => !beforeKeys.has(key(f)));
  const byCause = {};
  for (const f of removed) (byCause[cause(f)] ??= []).push(f);
  return { name, before, after, removed, still, added, byCause };
}

const results = [
  analyse("Trivy 0.74.0", loadTrivy("baseline-trivy.json"), loadTrivy("echo-trivy.json")),
  analyse("Grype 0.119.0", loadGrype("baseline-grype.json"), loadGrype("echo-grype.json")),
];

// --- markdown helpers ------------------------------------------------------------
const uniq = (fs) => new Set(fs.map((f) => f.id)).size;
const count = (fs, s) => fs.filter((f) => f.severity === s).length;
const ch = (fs) => fs.filter((f) => f.severity === "Critical" || f.severity === "High");
const usedSev = (fs) => SEVERITIES.filter((s) => fs.some((f) => f.severity === s));
const table = (head, rows) =>
  [`| ${head.join(" | ")} |`, `|${head.map((h, i) => (i === 0 ? "---" : "---:")).join("|")}|`, ...rows.map((r) => `| ${r.join(" | ")} |`)].join("\n");
function byPackage(fs) {
  const m = new Map();
  for (const f of fs) {
    const e = m.get(f.pkg) ?? { pkg: f.pkg, n: 0, crit: 0, high: 0 };
    e.n++;
    if (f.severity === "Critical") e.crit++;
    if (f.severity === "High") e.high++;
    m.set(f.pkg, e);
  }
  return [...m.values()].sort((a, b) => b.crit + b.high - (a.crit + a.high) || b.n - a.n || a.pkg.localeCompare(b.pkg));
}

// --- report ------------------------------------------------------------------------
const L = [];
const p = (...s) => L.push(...s);
const trivyInfo = JSON.parse(readFileSync(R("echo-trivy.json"), "utf8"));

p("# Scan diff: nginx:1.25-bookworm → echo-nginx:1.25.5", "");
p("Generated by `tools/scan-diff.mjs` (`make scan`) from the JSON reports in this directory.", "");
p("| | Baseline | Echo |", "|---|---|---|");
p(`| Image | \`${UPSTREAM}\` | \`${ECHO}\` |`);
p(`| Reports | \`baseline-trivy.json\`, \`baseline-grype.json\` | \`echo-trivy.json\`, \`echo-grype.json\` |`);
p(`| Installed packages | ${pkgsBase.size} (\`baseline-packages.txt\`) | ${pkgsEcho.size} (\`echo-packages.txt\`) |`);
p(`| Debian | 12.5 | ${trivyInfo.Metadata?.OS?.Name ?? "?"} |`, "");
p("Scanner versions and vulnerability DBs are identical for both scans (see `scan-info.md`), so every difference");
p("below comes from the image, not from scanner or DB changes.", "");
p("A *finding* is one (package, vulnerability) pair; one CVE in two packages counts twice.", "");

p("## Severity counts", "");
for (const r of results) {
  p(`### ${r.name}`, "");
  const sevs = usedSev([...r.before, ...r.after]);
  p(table(["Severity", "Baseline findings", "Echo findings", "Change"], [
    ...sevs.map((s) => [s, count(r.before, s), count(r.after, s), count(r.after, s) - count(r.before, s)]),
    ["**Total**", `**${r.before.length}**`, `**${r.after.length}**`, `**${r.after.length - r.before.length}**`],
    ["Unique IDs", uniq(r.before), uniq(r.after), uniq(r.after) - uniq(r.before)],
  ]), "");
}

p("## Key CVEs", "");
p(table(["CVE", ...results.flatMap((r) => [`${r.name} baseline`, `${r.name} echo`])],
  WATCH.map((id) => [id, ...results.flatMap((r) => [r.before, r.after].map((fs) => {
    const hits = fs.filter((f) => f.id === id);
    return hits.length ? hits.map((f) => `${f.pkg} (${f.severity})`).join(", ") : "not reported";
  }))])), "");

p("## Removed findings by cause", "");
p(table(["Cause", ...results.flatMap((r) => [`${r.name} findings`, `${r.name} Crit+High`])],
  [...Object.keys(CAUSES).map((c) => [CAUSES[c], ...results.flatMap((r) => [(r.byCause[c] ?? []).length, ch(r.byCause[c] ?? []).length])]),
   ["**Total removed**", ...results.flatMap((r) => [`**${r.removed.length}**`, `**${ch(r.removed).length}**`])]]), "");
p("Attribution rules, applied in order:", "");
p("1. Package is `libssl3` or `openssl`: **OpenSSL bump**.");
p(`2. Package is not installed in echo and is one of the ${moduleSet.size} packages apt removes together with the four`);
p("   `nginx-module-*` packages in the upstream image: **removed modules**.");
p("3. Package is installed in both images but at a different version: **newer Debian packages**. This covers");
p("   the newer `debian:bookworm-slim` base and packages installed from the current bookworm repositories");
p("   (curl, ca-certificates, …).");
p("4. Anything else: **other** (listed individually below).", "");

for (const c of Object.keys(CAUSES)) {
  p(`### ${CAUSES[c]}`, "");
  for (const r of results) {
    const fs = r.byCause[c] ?? [];
    if (!fs.length) { p(`**${r.name}:** none.`, ""); continue; }
    p(`**${r.name}:** ${fs.length} findings (${ch(fs).length} Critical/High) in ${byPackage(fs).length} packages.`, "");
    if (c === "other") {
      p(table(["Package", "Vulnerability", "Severity", "Baseline version", "Echo version"],
        fs.map((f) => [f.pkg, f.id, f.severity, f.version, pkgsEcho.get(f.pkg) ?? "not installed"])), "");
    } else {
      p(table(["Package", "Baseline version", "Echo version", "Removed", "Crit", "High"],
        byPackage(fs).map((e) => [e.pkg, pkgsBase.get(e.pkg) ?? "?", pkgsEcho.get(e.pkg) ?? "not installed", e.n, e.crit, e.high])), "");
    }
  }
}

p("## Findings still present", "");
for (const r of results) {
  const fixable = r.still.filter((f) => f.fixed);
  p(`### ${r.name}: ${r.still.length} findings (${ch(r.still).length} Critical/High, ${fixable.length} with a fix version listed)`, "");
  p(table(["Package", "Echo version", "Findings", "Crit", "High"],
    byPackage(r.still).slice(0, 15).map((e) => [e.pkg, pkgsEcho.get(e.pkg) ?? "?", e.n, e.crit, e.high])), "");
  if (byPackage(r.still).length > 15) p(`(top 15 of ${byPackage(r.still).length} packages by Critical+High)`, "");
  const chStill = ch(r.still);
  if (chStill.length) {
    p("<details><summary>All Critical/High findings still present</summary>", "");
    p(table(["Package", "Vulnerability", "Severity", "State", "Fixed in"],
      chStill.sort((a, b) => a.pkg.localeCompare(b.pkg) || a.id.localeCompare(b.id))
        .map((f) => [f.pkg, f.id, f.severity, f.state || "–", f.fixed || "–"])), "");
    p("</details>", "");
  }
}

p("## New findings in echo-nginx", "");
for (const r of results) {
  if (!r.added.length) { p(`**${r.name}:** none.`, ""); continue; }
  p(`**${r.name}:** ${r.added.length} findings (${ch(r.added).length} Critical/High).`, "");
  p(table(["Package", "Version", "Vulnerability", "Severity", "Baseline version of package"],
    r.added.sort((a, b) => a.pkg.localeCompare(b.pkg) || a.id.localeCompare(b.id))
      .map((f) => [f.pkg, f.version, f.id, f.severity, pkgsBase.get(f.pkg) ?? "not installed"])), "");
}

p("## Notes", "");
p("- **The \"new\" Trivy findings on `nginx` are not new vulnerabilities.** They are the same three Debian records");
p("  (CVE-2009-4487, CVE-2013-0337, CVE-2023-44487) that Grype matches by package name in *both* images. On the");
p("  baseline, Trivy 0.74.0 skipped the nginx.org package (maintainer `NGINX Packaging`); our package has a");
p("  different maintainer and version string, and Trivy now matches it against Debian's `nginx` source package.");
p("- **Neither scanner checks nginx itself against nginx.org's advisories.** CVE-2024-7347 is not reported on either");
p("  image, so its fix cannot show up here. The evidence is the build (`build/patches/`) and the compatibility test");
p("  check `cve-2024-7347`, recorded in `vex/CVE-2024-7347.openvex.json`. A binary-level scan that does report it, and");
p("  the VEX suppressing it on our image only, is in `vex-demo.md` (`make vex`). Residual nginx CVEs: `TRIAGE.md`.");
p("- **The removed modules are counted separately on purpose.** They are an extra hardening step (smaller attack");
p("  surface), not one of the selected CVE fixes.", "");

writeFileSync(R("diff.md"), L.join("\n"));
for (const r of results) {
  console.log(`${r.name}: ${r.before.length} -> ${r.after.length} findings; removed ${r.removed.length} ` +
    `(${Object.keys(CAUSES).map((c) => `${c}=${(r.byCause[c] ?? []).length}`).join(" ")}); still ${r.still.length}; new ${r.added.length}`);
}
console.log("wrote reports/diff.md");
