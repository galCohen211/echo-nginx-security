// Container lifecycle via the docker CLI.
import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";
import { rawExchange } from "./http.js";

const run = promisify(execFile);

export const CONTAINER_LABEL = "echo-nginx-compat-test=1";

export interface Target {
  label: string;
  image: string;
}

export interface Container extends Target {
  name: string;
  ports: { default: number; custom: number };
}

export async function docker(...args: string[]): Promise<string> {
  try {
    const { stdout } = await run("docker", args, { maxBuffer: 64 * 1024 * 1024 });
    return stdout;
  } catch (err) {
    const e = err as { stderr?: string; message: string };
    throw new Error(`docker ${args.join(" ")} failed: ${(e.stderr ?? e.message).trim()}`);
  }
}

export async function ensureImage(image: string): Promise<void> {
  try {
    await docker("image", "inspect", "--format", "{{.Id}}", image);
  } catch {
    throw new Error(`image ${image} not found locally (run \`make image\`, or \`docker pull\` for upstream)`);
  }
}

export interface Mounts {
  confFile: string;
  srvDir: string;
}

// Both ports are published on 127.0.0.1 with a host port chosen by Docker,
// so the test never collides with ports already in use.
export async function startContainer(t: Target, mounts: Mounts): Promise<Container> {
  const name = `compat-${t.label}-${process.pid}-${randomBytes(3).toString("hex")}`;
  await docker(
    "run", "-d", "--rm", "--name", name, "--label", CONTAINER_LABEL,
    "-p", "127.0.0.1::80", "-p", "127.0.0.1::8080",
    "-v", `${mounts.confFile}:/etc/nginx/conf.d/compat.conf:ro`,
    "-v", `${mounts.srvDir}:/srv/compat:ro`,
    t.image,
  );
  const port = async (p: string) => {
    const out = await docker("port", name, p);
    const m = /:(\d+)\s*$/m.exec(out.trim().split("\n")[0]);
    if (!m) throw new Error(`could not parse published port for ${name} ${p}: ${out}`);
    return Number(m[1]);
  };
  return { ...t, name, ports: { default: await port("80/tcp"), custom: await port("8080/tcp") } };
}

// Ready = both servers answer GET with 200.
export async function waitReady(c: Container, timeoutMs = 30_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  const probe = (port: number, path: string) =>
    rawExchange(port, `GET ${path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n`, { timeoutMs: 2000 });
  while (Date.now() < deadline) {
    try {
      const [a, b] = await Promise.all([probe(c.ports.default, "/"), probe(c.ports.custom, "/header")]);
      if (a.responses[0]?.status === 200 && b.responses[0]?.status === 200) return;
    } catch {
      // not accepting connections yet
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  const logs = await containerLogs(c).catch(() => "(no logs)");
  throw new Error(`${c.label} (${c.image}) not ready after ${timeoutMs} ms. Logs:\n${logs}`);
}

export async function containerLogs(c: Container): Promise<string> {
  const { stdout, stderr } = await run("docker", ["logs", c.name], { maxBuffer: 16 * 1024 * 1024 });
  return stdout + stderr;
}

export async function removeContainers(cs: Container[]): Promise<void> {
  await Promise.all(cs.map((c) => docker("rm", "-f", c.name).catch(() => undefined)));
}
