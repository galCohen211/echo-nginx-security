// Builds the directory mounted at /srv/compat in both containers.
// Everything is deterministic and every file gets the same fixed mtime, so
// ETag and Last-Modified are identical in both containers by construction.
import { copyFileSync, mkdirSync, readdirSync, rmSync, utimesSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const TEST_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const FIXTURES_DIR = path.join(TEST_DIR, "fixtures");
export const WORK_DIR = path.join(TEST_DIR, ".work");

export const FIXED_MTIME = new Date("2024-04-16T15:00:00Z");
export const LARGE_SIZE = 5 * 1024 * 1024;

export interface PreparedFixtures {
  confFile: string;
  srvDir: string;
}

export function prepareFixtures(): PreparedFixtures {
  const srv = path.join(WORK_DIR, "srv");
  rmSync(srv, { recursive: true, force: true });
  for (const d of ["static", "large", "media"]) mkdirSync(path.join(srv, d), { recursive: true });

  for (const f of readdirSync(path.join(FIXTURES_DIR, "static"))) {
    copyFileSync(path.join(FIXTURES_DIR, "static", f), path.join(srv, "static", f));
  }
  writeFileSync(path.join(srv, "large", "blob.bin"), pseudoRandom(LARGE_SIZE, 0x5eed));
  writeFileSync(path.join(srv, "media", "sample.mp4"), buildMp4(VALID_STSC));
  writeFileSync(path.join(srv, "media", "cve-2024-7347.mp4"), buildMp4(UNORDERED_STSC));

  for (const d of ["static", "large", "media"]) {
    for (const f of readdirSync(path.join(srv, d))) utimesSync(path.join(srv, d, f), FIXED_MTIME, FIXED_MTIME);
  }
  return { confFile: path.join(FIXTURES_DIR, "compat.conf"), srvDir: srv };
}

// xorshift32: same bytes on every run and platform.
function pseudoRandom(size: number, seed: number): Buffer {
  const buf = Buffer.alloc(size);
  let x = seed >>> 0;
  for (let i = 0; i < size; i += 4) {
    x ^= x << 13; x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5; x >>>= 0;
    buf.writeUInt32LE(x, i);
  }
  return buf;
}

// --- minimal MP4 -------------------------------------------------------------
// One video track, 12 samples of 1 s each, stored in 4 chunks of 2, 2, 4, 4
// samples. The sample entry is a dummy 'mp4v': ngx_http_mp4_module copies stsd
// verbatim and only interprets the sample tables, which is all we exercise.

const CHUNK_SAMPLES = [2, 2, 4, 4];
const SAMPLES = CHUNK_SAMPLES.reduce((a, b) => a + b, 0);
const SAMPLE_SIZE = 256;
const TIMESCALE = 1000;
const DELTA = 1000;

// stsc entries: [first_chunk, samples_per_chunk]
const VALID_STSC: Array<[number, number]> = [[1, 2], [3, 4]];
// CVE-2024-7347 trigger: first_chunk goes backwards (3 -> 2). Fixed nginx
// rejects this ("unordered mp4 stsc chunks"); unpatched nginx computes
// (next_chunk - chunk) * samples with an unsigned underflow.
const UNORDERED_STSC: Array<[number, number]> = [[1, 2], [3, 4], [2, 4]];

const u32 = (...v: number[]) => {
  const b = Buffer.alloc(4 * v.length);
  v.forEach((n, i) => b.writeUInt32BE(n >>> 0, 4 * i));
  return b;
};
const u16 = (...v: number[]) => {
  const b = Buffer.alloc(2 * v.length);
  v.forEach((n, i) => b.writeUInt16BE(n, 2 * i));
  return b;
};
const box = (type: string, ...parts: Buffer[]) => {
  const payload = Buffer.concat(parts);
  return Buffer.concat([u32(8 + payload.length), Buffer.from(type, "latin1"), payload]);
};
const fullbox = (type: string, version: number, flags: number, ...parts: Buffer[]) =>
  box(type, u32(((version & 0xff) << 24) | (flags & 0xffffff)), ...parts);
const MATRIX = u32(0x00010000, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000);

function moov(chunkOffsets: number[], stsc: Array<[number, number]>): Buffer {
  const duration = SAMPLES * DELTA;
  const syncSamples = Array.from({ length: SAMPLES / 2 }, (_, i) => 2 * i + 1);
  const stbl = box(
    "stbl",
    fullbox("stsd", 0, 0, u32(1), box("mp4v", Buffer.alloc(6), u16(1), Buffer.alloc(70))),
    fullbox("stts", 0, 0, u32(1, SAMPLES, DELTA)),
    fullbox("stss", 0, 0, u32(syncSamples.length, ...syncSamples)),
    fullbox("stsc", 0, 0, u32(stsc.length), ...stsc.map(([first, n]) => u32(first, n, 1))),
    fullbox("stsz", 0, 0, u32(0, SAMPLES), u32(...Array<number>(SAMPLES).fill(SAMPLE_SIZE))),
    fullbox("stco", 0, 0, u32(chunkOffsets.length, ...chunkOffsets)),
  );
  return box(
    "moov",
    fullbox("mvhd", 0, 0, u32(0, 0, TIMESCALE, duration, 0x00010000), u16(0x0100), Buffer.alloc(10), MATRIX,
      Buffer.alloc(24), u32(2)),
    box(
      "trak",
      fullbox("tkhd", 0, 3, u32(0, 0, 1, 0, duration), Buffer.alloc(8), u16(0, 0, 0, 0), MATRIX,
        u32(320 << 16, 240 << 16)),
      box(
        "mdia",
        fullbox("mdhd", 0, 0, u32(0, 0, TIMESCALE, duration), u16(0x55c4, 0)),
        fullbox("hdlr", 0, 0, u32(0), Buffer.from("vide"), Buffer.alloc(12), Buffer.from("VideoHandler\0")),
        box("minf", fullbox("vmhd", 0, 1, Buffer.alloc(8)),
          box("dinf", fullbox("dref", 0, 0, u32(1), fullbox("url ", 0, 1))), stbl),
      ),
    ),
  );
}

function buildMp4(stsc: Array<[number, number]>): Buffer {
  const ftyp = box("ftyp", Buffer.from("isom"), u32(512), Buffer.from("isomiso2mp41"));
  const moovSize = moov(CHUNK_SAMPLES.map(() => 0), stsc).length;
  let offset = ftyp.length + moovSize + 8;
  const chunkOffsets = CHUNK_SAMPLES.map((n) => {
    const o = offset;
    offset += n * SAMPLE_SIZE;
    return o;
  });
  const samples = Array.from({ length: SAMPLES }, (_, i) => Buffer.alloc(SAMPLE_SIZE, (i * 7 + 1) & 0xff));
  return Buffer.concat([ftyp, moov(chunkOffsets, stsc), box("mdat", ...samples)]);
}
