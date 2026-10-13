// Entry point for `make test`: checks prerequisites, installs dependencies,
// builds the TypeScript test and runs it. Lives in Node instead of the
// Makefile so the recipe works the same under cmd.exe and sh.
//
//   node test/scripts/run.cjs [--upstream IMAGE] [--candidate IMAGE]
//
// Written in deliberately old JavaScript (no async, no newer syntax) so even an
// old Node can parse it and print the version error instead of a syntax error.
"use strict";

var childProcess = require("child_process");
var path = require("path");

var TEST_DIR = path.resolve(__dirname, "..");
var MIN_NODE_MAJOR = 20;

function fail(msg, code) {
  console.error("ERROR: " + msg);
  process.exit(code === undefined ? 1 : code);
}

function arg(name, fallback) {
  var i = process.argv.indexOf("--" + name);
  return i >= 0 && process.argv[i + 1] ? process.argv[i + 1] : fallback;
}

// Runs a command with inherited stdio; returns its exit status.
// npm is a .cmd script on Windows, which Node only spawns through a shell;
// the arguments here are fixed strings, never user input.
function run(cmd, args, opts) {
  opts = opts || {};
  var useShell = process.platform === "win32" && cmd === "npm";
  var res = childProcess.spawnSync(cmd, args, {
    cwd: opts.cwd || TEST_DIR,
    env: opts.env || process.env,
    stdio: opts.quiet ? "ignore" : "inherit",
    shell: useShell,
  });
  if (res.error) {
    if (res.error.code === "ENOENT") fail("'" + cmd + "' not found in PATH.");
    fail("could not run " + cmd + ": " + res.error.message);
  }
  return res.status === null ? 1 : res.status;
}

function step(title) {
  console.log("\n==> " + title);
}

var major = Number(process.versions.node.split(".")[0]);
if (major < MIN_NODE_MAJOR) {
  fail("Node.js " + MIN_NODE_MAJOR + "+ is required for 'make test', found " + process.version + ".");
}

var upstream = arg("upstream", "nginx:1.25-bookworm");
var candidate = arg("candidate", "echo-nginx:1.25.5");

step("checking Docker");
if (run("docker", ["version", "--format", "{{.Server.Version}}"], { quiet: true }) !== 0) {
  fail("Docker is not running (docker version failed).");
}

step("checking images: " + upstream + ", " + candidate);
if (run("docker", ["image", "inspect", upstream], { quiet: true }) !== 0) {
  console.log(upstream + " not present locally, pulling");
  if (run("docker", ["pull", upstream]) !== 0) fail("docker pull " + upstream + " failed.");
}
if (run("docker", ["image", "inspect", candidate], { quiet: true }) !== 0) {
  fail("image " + candidate + " not found. Build it first with 'make image'.");
}

step("installing dependencies (npm ci)");
if (run("npm", ["ci", "--no-audit", "--no-fund"]) !== 0) fail("npm ci failed.");

step("building (tsc)");
if (run("npm", ["run", "build"]) !== 0) fail("TypeScript build failed.");

step("running compatibility test");
var env = Object.assign({}, process.env, { UPSTREAM_IMAGE: upstream, CANDIDATE_IMAGE: candidate });
process.exit(run(process.execPath, [path.join(TEST_DIR, "dist", "main.js")], { env: env }));
