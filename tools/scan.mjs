// Entry point for `make scan`: scans the image with the pinned Trivy and Grype
// versions (same flags as the baseline, see reports/scan-info.md), records the
// DB versions, then writes reports/diff.md via tools/scan-diff.mjs.
//
//   node tools/scan.mjs [--image echo-nginx:1.25.5] [--prefix echo]
//
// Kept in Node rather than the Makefile so it runs the same under cmd.exe and sh.
import { execFileSync, spawnSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import path from "node:path";

// Pinned in reports/scan-info.md; the final rescan must use exactly these.
const TRIVY = "aquasec/trivy:0.74.0@sha256:62b1e65e8869bc4b4c6aa4fa2b21595256c7c2f6018a9d9ad61caf87187c1969";
const GRYPE = "anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3";

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const image = arg("image", "echo-nginx:1.25.5");
const prefix = arg("prefix", "echo");

const ROOT = process.cwd();
const REPORTS = path.join(ROOT, "reports");
const SOCK = process.platform === "win32" ? "//var/run/docker.sock" : "/var/run/docker.sock";
const sockMount = ["-v", `${SOCK}:/var/run/docker.sock`];
const trivyCache = ["-v", "trivy-cache:/root/.cache/"];
const grypeCache = ["-e", "GRYPE_DB_CACHE_DIR=/cache", "-v", "grype-cache:/cache"];
const out = ["-v", `${REPORTS}:/out`];

function docker(args, { capture = false } = {}) {
  console.log(`$ docker ${args.join(" ")}`);
  if (capture) return execFileSync("docker", args, { encoding: "utf8" });
  const r = spawnSync("docker", args, { stdio: "inherit" });
  if (r.error) throw new Error(`docker: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`docker ${args[0]} ... exited with ${r.status}`);
  return "";
}

try {
  docker(["image", "inspect", "--format", "{{.Id}}", image], { capture: true });
} catch {
  console.error(`ERROR: image ${image} not found. Build it with 'make image'.`);
  process.exit(1);
}

try {
  console.log("\n==> refreshing vulnerability DBs");
  docker(["run", "--rm", ...trivyCache, TRIVY, "image", "--download-db-only", "--no-progress"]);
  docker(["run", "--rm", ...grypeCache, GRYPE, "db", "update"]);

  console.log(`\n==> Trivy: ${image}`);
  docker(["run", "--rm", ...sockMount, ...trivyCache, ...out, TRIVY, "image", "--no-progress", "--scanners", "vuln",
    "--format", "json", "--output", `/out/${prefix}-trivy.json`, image]);
  docker(["run", "--rm", ...trivyCache, ...out, TRIVY, "convert", "--format", "table",
    "--output", `/out/${prefix}-trivy.txt`, `/out/${prefix}-trivy.json`]);

  console.log(`\n==> Grype: ${image}`);
  docker(["run", "--rm", "-e", "GRYPE_DB_AUTO_UPDATE=false", ...sockMount, ...grypeCache, ...out, GRYPE,
    `docker:${image}`, "-q", "-o", `json=/out/${prefix}-grype.json`, "-o", `table=/out/${prefix}-grype.txt`]);

  console.log("\n==> recording scanner and DB versions");
  // Only the "Vulnerability DB:" section (the first "Version:" line is Trivy's own).
  const trivyVersion = docker(["run", "--rm", ...trivyCache, TRIVY, "version"], { capture: true })
    .split("Vulnerability DB:")[1]?.split(/Java DB:|Check Bundle:/)[0] ?? "";
  const grypeDb = docker(["run", "--rm", ...grypeCache, GRYPE, "db", "status"], { capture: true });
  const field = (text, label) => (new RegExp(`${label}:\\s*(.+)`).exec(text)?.[1] ?? "?").trim();
  const imageId = docker(["image", "inspect", "--format", "{{.Id}}", image], { capture: true }).trim();
  const md = [
    `# Scan info: ${image}`,
    "",
    "Written by `tools/scan.mjs` (`make scan`).",
    "",
    "| Item | Value |",
    "|------|-------|",
    `| Scan date | ${new Date().toISOString()} |`,
    `| Image | \`${image}\` (\`${imageId}\`) |`,
    `| Trivy | \`${TRIVY}\` |`,
    `| Trivy DB | schema v${field(trivyVersion, "Version")}, updated ${field(trivyVersion, "UpdatedAt")} |`,
    `| Grype | \`${GRYPE}\` |`,
    `| Grype DB | schema ${field(grypeDb, "Schema")}, built ${field(grypeDb, "Built")} |`,
    "",
    `Reports: \`${prefix}-trivy.json\`, \`${prefix}-trivy.txt\`, \`${prefix}-grype.json\`, \`${prefix}-grype.txt\`.`,
    "Same flags as the baseline scan (see `scan-info.md`).",
    "",
  ].join("\n");
  writeFileSync(path.join(REPORTS, `${prefix}-scan-info.md`), md);
  console.log(md);

  console.log("==> comparing with baseline");
  const r = spawnSync(process.execPath, [path.join(ROOT, "tools", "scan-diff.mjs")], { stdio: "inherit" });
  process.exit(r.status ?? 1);
} catch (err) {
  console.error(`ERROR: ${err.message}`);
  process.exit(1);
}
