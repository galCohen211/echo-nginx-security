// Entry point for `make vex`: generates the CVE-2024-7347 VEX document for the
// image that is currently built, then shows that it suppresses CVE-2024-7347 on
// that image and only on that image.
//
//   node tools/vex.mjs [--image echo-nginx:1.25.5] [--upstream nginx:1.25-bookworm] [--out-dir reports]
//
// The statement is scoped to one image digest, and the image build is not
// byte-reproducible, so the document is generated per build from
// vex/CVE-2024-7347.openvex.template.json into <out-dir>/vex/. The committed
// vex/CVE-2024-7347.openvex.json is the example generated for the author's build.
//
// For each image: a Syft SBOM restricted to the binary cataloger (so the
// nginx binary is identified as pkg:generic/nginx@1.25.5 and matched by CPE),
// then Grype on that SBOM without and with --vex. Why binary-only: see
// vex/README.md. Outputs go to <out-dir>/vex/ and <out-dir>/vex-demo.md.
// Exit code 0 only if: our image reports the CVE without VEX, not with VEX, and
// upstream reports it in both runs.
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

// Pinned: Syft is the version built into the pinned Grype (Syft v1.52.0).
const SYFT = "anchore/syft:v1.52.0@sha256:500e2d872ac019436926e8322b4fc1f39441d94d21f6f4046c6ff29b30e8cb02";
const GRYPE = "anchore/grype:v0.119.0@sha256:8c2c9234a345577a6d321a4753aa3ee1276d8975c8452d2344a56b57733ecad3";
const CVE = "CVE-2024-7347";

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
};
const IMAGES = [
  { label: "echo", image: arg("image", "echo-nginx:1.25.5") },
  { label: "upstream", image: arg("upstream", "nginx:1.25-bookworm") },
];

const ROOT = process.cwd();
const OUT_ROOT = path.resolve(ROOT, arg("out-dir", "reports"));
const OUT = path.join(OUT_ROOT, "vex");
const TEMPLATE = path.join(ROOT, "vex", "CVE-2024-7347.openvex.template.json");
const EXAMPLE = path.join(ROOT, "vex", "CVE-2024-7347.openvex.json");
const VEX_FILE = "CVE-2024-7347.openvex.json";
const SOCK = process.platform === "win32" ? "//var/run/docker.sock" : "/var/run/docker.sock";
const grypeCache = ["-e", "GRYPE_DB_CACHE_DIR=/cache", "-v", "grype-cache:/cache"];

function docker(args, { capture = false } = {}) {
  console.log(`$ docker ${args.join(" ")}`);
  if (capture) return execFileSync("docker", args, { encoding: "utf8" });
  const r = spawnSync("docker", args, { stdio: "inherit" });
  if (r.error) throw new Error(`docker: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`docker ${args[0]} ... exited with ${r.status}`);
  return "";
}
const fail = (msg) => {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
};

// --- generate the VEX document for the image currently built --------------------
const ECHO = IMAGES[0].image;
let repoDigests;
try {
  repoDigests = JSON.parse(docker(["image", "inspect", "--format", "{{json .RepoDigests}}", ECHO], { capture: true }));
} catch {
  fail(`image ${ECHO} not found. Build it with 'make image'.`);
}
// Grype scopes OCI products by the image's repo digest, as recorded by Syft.
// Docker's containerd image store sets it for locally built images; the
// classic store leaves it empty, and then the statement cannot be scoped.
const repoDigest = (repoDigests ?? []).find((d) => d.startsWith(`${ECHO.split(":")[0]}@`)) ?? repoDigests?.[0];
const echoDigest = repoDigest?.split("@")[1];
if (!echoDigest) {
  fail(`${ECHO} has no repo digest (docker image inspect shows RepoDigests: []).\n` +
    "This happens with Docker's classic image store. The VEX statement is scoped by digest, so it cannot be\n" +
    "generated. Enable the containerd image store (Docker Desktop: Settings > General > 'Use containerd for\n" +
    "pulling and storing images'; Docker Engine: \"features\": {\"containerd-snapshotter\": true} in daemon.json),\n" +
    "rebuild with 'make image', and run 'make vex' again.");
}
const repoName = repoDigest.split("@")[0];

const debInfo = docker(["run", "--rm", "--entrypoint", "sh", ECHO, "-c",
  "dpkg-query -W -f '${Version} ${Architecture}' nginx && echo \" $(cat /etc/debian_version)\""], { capture: true }).trim();
const [debVersion, debArch, debianVersion] = debInfo.split(/\s+/);
const values = {
  IMAGE_REF: ECHO,
  IMAGE_DIGEST: echoDigest,
  IMAGE_PURL: `pkg:oci/${repoName}@${encodeURIComponent(echoDigest)}`,
  DEB_PURL: `pkg:deb/debian/nginx@${encodeURIComponent(debVersion)}?arch=${debArch}&distro=debian-${debianVersion}`,
  TIMESTAMP: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
};
const rendered = readFileSync(TEMPLATE, "utf8").replace(/\{\{(\w+)\}\}/g, (m, k) => {
  if (!(k in values)) fail(`unknown placeholder ${m} in ${path.basename(TEMPLATE)}`);
  return values[k];
});
JSON.parse(rendered); // must still be valid JSON
mkdirSync(OUT, { recursive: true });
writeFileSync(path.join(OUT, VEX_FILE), rendered);
console.log(`generated ${path.relative(ROOT, path.join(OUT, VEX_FILE))} for ${ECHO} (${echoDigest})`);

let exampleNote = "the committed example `vex/CVE-2024-7347.openvex.json` is missing";
if (existsSync(EXAMPLE)) {
  const ex = JSON.parse(readFileSync(EXAMPLE, "utf8")).statements[0].products[0]["@id"];
  exampleNote = ex === values.IMAGE_PURL
    ? "same digest as the committed example `vex/CVE-2024-7347.openvex.json` (the author's build)"
    : `different from the committed example \`vex/CVE-2024-7347.openvex.json\` (\`${ex}\`, the author's build); expected after a rebuild`;
}
console.log(`image digest: ${exampleNote.replace(/`/g, "")}`);
const results = {};
try {
  console.log("\n==> refreshing Grype DB");
  docker(["run", "--rm", ...grypeCache, GRYPE, "db", "update"]);

  for (const { label, image } of IMAGES) {
    console.log(`\n==> ${label}: binary SBOM of ${image}`);
    docker(["run", "--rm", "-v", `${SOCK}:/var/run/docker.sock`, "-v", `${OUT}:/out`, SYFT, `docker:${image}`, "-q",
      "--override-default-catalogers", "binary-classifier-cataloger", "-o", `syft-json=/out/${label}-binaries.syft.json`]);
    for (const withVex of [false, true]) {
      const name = `${label}-grype${withVex ? "-vex" : ""}`;
      console.log(`\n==> ${label}: grype ${withVex ? "with" : "without"} --vex`);
      docker(["run", "--rm", "-e", "GRYPE_DB_AUTO_UPDATE=false", ...grypeCache, "-v", `${OUT}:/out`,
        GRYPE, `sbom:/out/${label}-binaries.syft.json`, "-q",
        ...(withVex ? ["--vex", `/out/${VEX_FILE}`] : []),
        "-o", `json=/out/${name}.json`, "-o", `table=/out/${name}.txt`]);
      const j = JSON.parse(readFileSync(path.join(OUT, `${name}.json`), "utf8"));
      results[name] = {
        matches: j.matches.length,
        reported: j.matches.filter((m) => m.vulnerability.id === CVE).map((m) => m.artifact.purl),
        ignored: (j.ignoredMatches ?? []).filter((m) => m.vulnerability.id === CVE)
          .map((m) => `${m.artifact.purl} (${m.appliedIgnoreRules.map((r) => `${r.namespace}: ${r["vex-status"] ?? "?"}`).join(", ")})`),
        nginxCves: j.matches.filter((m) => m.artifact.name === "nginx").length,
      };
    }
  }
} catch (err) {
  fail(err.message);
}

const r = results;
const checks = [
  [`echo without --vex reports ${CVE}`, r["echo-grype"].reported.length > 0],
  [`echo with --vex does not report ${CVE}`, r["echo-grype-vex"].reported.length === 0],
  [`echo with --vex lists ${CVE} as ignored by VEX`, r["echo-grype-vex"].ignored.length > 0],
  [`upstream without --vex reports ${CVE}`, r["upstream-grype"].reported.length > 0],
  [`upstream with --vex still reports ${CVE} (statement is scoped to our digest)`, r["upstream-grype-vex"].reported.length > 0],
];

const row = (label, image, name, withVex) => {
  const x = r[name];
  return `| ${label} (\`${image}\`) | ${withVex ? "yes" : "no"} | ${x.matches} | ${x.nginxCves} | ` +
    `${x.reported.length ? `**reported** (${x.reported.join(", ")})` : "not reported"} | ${x.ignored.join(", ") || "–"} | \`vex/${name}.json\` |`;
};
const md = [
  `# VEX demonstration: ${CVE}`,
  "",
  "Written by `tools/vex.mjs` (`make vex`).",
  "",
  `VEX document: \`vex/${VEX_FILE}\` in this directory, generated from \`vex/CVE-2024-7347.openvex.template.json\``,
  `for \`${IMAGES[0].image}\` with digest \`${echoDigest}\` (${exampleNote}).`,
  `Tools: \`${SYFT}\`, \`${GRYPE}\`.`,
  "",
  "Each image is described by a Syft SBOM restricted to the binary cataloger, which identifies",
  "`/usr/sbin/nginx` as `pkg:generic/nginx@1.25.5` (CPE `cpe:2.3:a:f5:nginx:1.25.5`). Grype then matches",
  "it against the upstream nginx CVEs. Why binary-only: see `vex/README.md`.",
  "",
  "| Image | `--vex` | Matches (all binaries) | nginx CVEs | " + CVE + " | Ignored by VEX | Output |",
  "|---|---|---:|---:|---|---|---|",
  row("echo", IMAGES[0].image, "echo-grype", false),
  row("echo", IMAGES[0].image, "echo-grype-vex", true),
  row("upstream", IMAGES[1].image, "upstream-grype", false),
  row("upstream", IMAGES[1].image, "upstream-grype-vex", true),
  "",
  "Both images contain a binary with the same identifier `pkg:generic/nginx@1.25.5`; the statement",
  "applies to ours only because the VEX product is our image digest.",
  "",
  "## Checks",
  "",
  ...checks.map(([t, ok]) => `- ${ok ? "PASS" : "FAIL"}: ${t}`),
  "",
].join("\n");
writeFileSync(path.join(OUT_ROOT, "vex-demo.md"), md);
console.log("\n" + md);
process.exit(checks.every(([, ok]) => ok) ? 0 : 1);
