// Compares the two images' responses and renders readable diffs.
import { createHash } from "node:crypto";
import type { ExchangeResult, HttpResponse } from "./http.js";

// Headers that cannot be identical between two separately started containers.
// Each one is still checked (see normalizeHeaders); it is never just dropped.
// Keep this list in sync with test/README.md.
export const NORMALIZED_HEADERS = [
  {
    header: "Date",
    rule: "must be present once in both responses, be a valid HTTP date, and differ by at most 120 s",
  },
];
const DATE_TOLERANCE_MS = 120_000;

export function compareExchanges(
  a: ExchangeResult,
  b: ExchangeResult,
  labels: [string, string],
  opts: { tolerateSocketError?: boolean } = {},
): string[] {
  const diffs: string[] = [];
  const [la, lb] = labels;
  if (a.responses.length !== b.responses.length) {
    diffs.push(`number of responses: ${la}=${a.responses.length} ${lb}=${b.responses.length}` +
      `\n    ${la}: ${a.responses.map((r) => r.statusLine).join(" | ") || "(none)"}` +
      `\n    ${lb}: ${b.responses.map((r) => r.statusLine).join(" | ") || "(none)"}`);
  }
  const n = Math.min(a.responses.length, b.responses.length);
  for (let i = 0; i < n; i++) {
    const prefix = n > 1 ? `response #${i + 1}: ` : "";
    diffs.push(...compareResponse(a.responses[i], b.responses[i], labels).map((d) => prefix + d));
  }
  if (!a.trailing.equals(b.trailing)) {
    diffs.push(`unparsed trailing bytes differ: ${la}=${a.trailing.length} B ${lb}=${b.trailing.length} B`);
  }
  if (a.timedOut !== b.timedOut) {
    diffs.push(`connection outcome: ${la} ${a.timedOut ? "timed out" : "closed"}, ${lb} ${b.timedOut ? "timed out" : "closed"}`);
  }
  if (!opts.tolerateSocketError && (a.socketError ?? "") !== (b.socketError ?? "")) {
    diffs.push(`socket error: ${la}=${a.socketError ?? "none"} ${lb}=${b.socketError ?? "none"}`);
  }
  return diffs;
}

function compareResponse(a: HttpResponse, b: HttpResponse, [la, lb]: [string, string]): string[] {
  const diffs: string[] = [];
  if (a.statusLine !== b.statusLine) diffs.push(`status line:\n    ${la}: ${a.statusLine}\n    ${lb}: ${b.statusLine}`);

  const { a: ha, b: hb, problems } = normalizeHeaders(a.headers, b.headers);
  diffs.push(...problems);
  const fa = ha.map(([k, v]) => `${k}: ${v}`);
  const fb = hb.map(([k, v]) => `${k}: ${v}`);
  if (fa.join("\n") !== fb.join("\n")) {
    const lines: string[] = [];
    for (let i = 0; i < Math.max(fa.length, fb.length); i++) {
      if (fa[i] === fb[i]) lines.push(`      ${fa[i]}`);
      else {
        if (fa[i] !== undefined) lines.push(`    - ${fa[i]}   (${la})`);
        if (fb[i] !== undefined) lines.push(`    + ${fb[i]}   (${lb})`);
      }
    }
    diffs.push(`headers differ (- ${la}, + ${lb}):\n${lines.join("\n")}`);
  }

  if (a.truncated || b.truncated) diffs.push(`body truncated: ${la}=${a.truncated} ${lb}=${b.truncated}`);
  if (!a.body.equals(b.body)) diffs.push(bodyDiff(a.body, b.body, la, lb));
  return diffs;
}

function normalizeHeaders(a: Array<[string, string]>, b: Array<[string, string]>) {
  const problems: string[] = [];
  const dates = [a, b].map((h) => h.filter(([k]) => k === "Date").map(([, v]) => v));
  if (dates[0].length !== dates[1].length) {
    problems.push(`Date header count differs: ${dates[0].length} vs ${dates[1].length}`);
  } else if (dates[0].length === 1) {
    const [ta, tb] = [Date.parse(dates[0][0]), Date.parse(dates[1][0])];
    if (Number.isNaN(ta) || Number.isNaN(tb)) problems.push(`invalid Date header: "${dates[0][0]}" / "${dates[1][0]}"`);
    else if (Math.abs(ta - tb) > DATE_TOLERANCE_MS) problems.push(`Date headers more than 120 s apart: "${dates[0][0]}" / "${dates[1][0]}"`);
  }
  const norm = (h: Array<[string, string]>) => h.map(([k, v]): [string, string] => (k === "Date" ? [k, "<checked>"] : [k, v]));
  return { a: norm(a), b: norm(b), problems };
}

function bodyDiff(a: Buffer, b: Buffer, la: string, lb: string): string {
  const sha = (x: Buffer) => createHash("sha256").update(x).digest("hex").slice(0, 16);
  let first = 0;
  while (first < a.length && first < b.length && a[first] === b[first]) first++;
  const head = `body differs: ${la}=${a.length} B (sha256 ${sha(a)}…) ${lb}=${b.length} B (sha256 ${sha(b)}…), first difference at byte ${first}`;
  const isText = (x: Buffer) => !x.subarray(0, 4096).includes(0);
  if (!isText(a) || !isText(b)) return head;
  const al = a.toString("utf8").split("\n");
  const bl = b.toString("utf8").split("\n");
  const lines: string[] = [];
  for (let i = 0; i < Math.max(al.length, bl.length) && lines.length < 40; i++) {
    if (al[i] !== bl[i]) {
      if (al[i] !== undefined) lines.push(`    - ${al[i]}`);
      if (bl[i] !== undefined) lines.push(`    + ${bl[i]}`);
    }
  }
  return `${head}\n${lines.join("\n")}`;
}
