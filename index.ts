// server.ts
// Express server that exposes an authenticated endpoint to dump Alkane storage
// from a RocksDB directory using ldb/sst_dump and returns structured JSON.
//
// Endpoint:
//   GET /dump/:alkaneId?token=YOUR_TOKEN
// Env:
//   DB_PATH=/data/.metashrew/mainnet
//   AUTH_TOKEN=secret
//   LDB_BIN=/usr/local/bin/ldb            (optional, defaults to "ldb")
//   SST_DUMP_BIN=/usr/local/bin/sst_dump  (optional, defaults to "sst_dump")
//   COLUMN_FAMILY=default                 (optional)
//   ENDIAN=le                             (optional: le|be)
//   PORT=7107

import express from "express";
import { spawn } from "child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import "dotenv/config";

// ---------- Config ----------
const DB_PATH = process.env.DB_PATH ?? "/data/.metashrew/mainnet";
const AUTH_TOKEN = process.env.AUTH_TOKEN ?? ""; // must be set
const LDB_BIN = process.env.LDB_BIN ?? "ldb";
const SST_DUMP_BIN = process.env.SST_DUMP_BIN ?? "sst_dump";
const COLUMN_FAMILY = process.env.COLUMN_FAMILY ?? "default";
const DEFAULT_ENDIAN: "le" | "be" =
  (process.env.ENDIAN as any) === "be" ? "be" : "le";
const PORT = Number(process.env.PORT ?? 7107);
const CHILD_TIMEOUT_MS = Number(process.env.CHILD_TIMEOUT_MS ?? 120_000);

if (!AUTH_TOKEN) {
  // eslint-disable-next-line no-console
  console.warn(
    "[WARN] AUTH_TOKEN is empty. Set AUTH_TOKEN to protect the endpoint."
  );
}

// ---------- Helpers ----------
function u128le(n: bigint): Buffer {
  let x = BigInt(n);
  const b = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}
function u128be(n: bigint): Buffer {
  let x = BigInt(n);
  const b = Buffer.alloc(16);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return b;
}
function parseAlkaneId(s: string): [bigint, bigint] {
  const m = s.match(/^([0-9]+):([0-9]+)$/);
  if (!m)
    throw new Error("AlkaneId must be 'A:B' with decimal u128 components");
  return [BigInt(m[1]), BigInt(m[2])];
}
function makePrefix(alkaneId: string, endian: "le" | "be"): Buffer {
  const [a, b] = parseAlkaneId(alkaneId);
  const enc = endian === "be" ? u128be : u128le;
  return Buffer.concat([
    Buffer.from("/alkanes/"),
    enc(a),
    enc(b),
    Buffer.from("/storage"),
  ]);
}
const toHex = (buf: Buffer) => "0x" + buf.toString("hex");
const fromHex = (h: string) => Buffer.from(h.replace(/^0x/i, ""), "hex");
const isPrintable = (buf: Buffer) =>
  buf.length > 0 && [...buf].every((b) => b >= 0x20 && b < 0x7f);
const toAscii = (buf: Buffer) => buf.toString("utf8");
const pretty = (buf: Buffer) =>
  [...buf]
    .map((c) =>
      c >= 0x20 && c < 0x7f
        ? String.fromCharCode(c)
        : `\\x${c.toString(16).padStart(2, "0")}`
    )
    .join("");

function normalizeSuffix(keyAscii: string): string {
  const idx = keyAscii.indexOf("/storage");
  let suffix = idx >= 0 ? keyAscii.slice(idx + "/storage".length) : keyAscii;
  if (suffix.startsWith("//")) suffix = suffix.slice(1);
  if (!suffix.startsWith("/")) suffix = "/" + suffix;
  return suffix;
}

function parseValue(buf: Buffer): any {
  if (isPrintable(buf)) {
    const text = toAscii(buf);
    const m = text.match(/^(\d+):([0-9a-fA-F]+)0*$/);
    if (m) return { text, block: Number(m[1]), hex: m[2].toLowerCase() };
    return { text };
  }
  return { hex: toHex(buf) };
}

// accept "=>" or "==>"
const KV_RE = /(0x[0-9a-fA-F]+)\s*={1,2}>\s*(0x[0-9a-fA-F]+)/;

function parseLdb(stdout: string) {
  const out: { kbuf: Buffer; vbuf: Buffer; khex: string; vhex: string }[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(KV_RE);
    if (!m) continue;
    const [, khex, vhex] = m;
    const kbuf = fromHex(khex);
    const vbuf = fromHex(vhex);
    out.push({
      kbuf,
      vbuf,
      khex: khex.toLowerCase(),
      vhex: vhex.toLowerCase(),
    });
  }
  return out;
}

function parseSstDump(stdout: string) {
  const out: { kbuf: Buffer; vbuf: Buffer; khex: string; vhex: string }[] = [];
  for (const line of stdout.split(/\r?\n/)) {
    const m = line.match(
      /^0x([0-9a-fA-F]+)\s+@\s+\d+:\s+\d+\s+={1,2}>\s+0x([0-9a-fA-F]+)$/
    );
    if (!m) continue;
    const kbuf = Buffer.from(m[1], "hex");
    const vbuf = Buffer.from(m[2], "hex");
    out.push({
      kbuf,
      vbuf,
      khex: "0x" + m[1].toLowerCase(),
      vhex: "0x" + m[2].toLowerCase(),
    });
  }
  return out;
}

function groupResults(
  recs: { kbuf: Buffer; vbuf: Buffer; khex: string; vhex: string }[]
) {
  const records: any[] = [];
  const bySuffix: Record<string, any[]> = {};
  const latestBySuffix: Record<string, any> = {};

  for (const r of recs) {
    const keyAscii = toAscii(r.kbuf);
    const suffix = normalizeSuffix(keyAscii);
    const valObj = parseValue(r.vbuf);

    records.push({
      key: suffix, // normalized key only
      rawKey: { ascii: pretty(r.kbuf), hex: r.khex },
      value: valObj,
      valueHex: r.vhex,
    });

    (bySuffix[suffix] ??= []).push(valObj);
    if (typeof valObj.block === "number") {
      const cur = latestBySuffix[suffix];
      if (!cur || valObj.block > cur.block) latestBySuffix[suffix] = valObj;
    }
  }
  return { count: records.length, records, bySuffix, latestBySuffix };
}

function spawnCapture(
  cmd: string,
  args: string[],
  timeoutMs = CHILD_TIMEOUT_MS
): Promise<string> {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    const to = setTimeout(() => {
      p.kill("SIGKILL");
      reject(new Error(`Timeout after ${timeoutMs}ms: ${cmd}`));
    }, timeoutMs);
    p.stdout.on("data", (d) => (out += d.toString()));
    p.stderr.on("data", (d) => (err += d.toString()));
    p.on("error", (e) => {
      clearTimeout(to);
      reject(e);
    });
    p.on("close", (code) => {
      clearTimeout(to);
      if (code !== 0) return reject(new Error(`${cmd} exited ${code}: ${err}`));
      resolve(out);
    });
  });
}

async function runLdbScan(params: {
  dbPath: string;
  cf: string;
  fromHex: string;
  toHex: string;
  useKeyHex: boolean;
}) {
  const secondary = fs.mkdtempSync(path.join(os.tmpdir(), "ldb_sec_"));
  const args = [
    `--db=${params.dbPath}`,
    `--secondary_path=${secondary}`,
    `--try_load_options`,
    `--column_family=${params.cf}`,
    `scan`,
    ...(params.useKeyHex ? ["--key_hex"] : []),
    `--from=${params.fromHex}`,
    `--to=${params.toHex}`,
    `--hex`,
  ];
  try {
    return await spawnCapture(LDB_BIN, args);
  } finally {
    try {
      fs.rmSync(secondary, { recursive: true, force: true });
    } catch {}
  }
}

async function runSstDump(params: {
  dbPath: string;
  fromHex: string;
  toHex: string;
}) {
  const args = [
    `--file=${params.dbPath}`,
    `--command=scan`,
    `--from=${params.fromHex}`,
    `--to=${params.toHex}`,
    `--input_key_hex`,
    `--output_hex`,
  ];
  return await spawnCapture(SST_DUMP_BIN, args);
}

async function dumpAlkane(
  alkaneId: string,
  endian: "le" | "be" = DEFAULT_ENDIAN
) {
  const prefix = makePrefix(alkaneId, endian);
  const fromHex = toHex(prefix);
  const toHexStr = toHex(Buffer.concat([prefix, Buffer.from([0xff])]));

  // Try ldb without --key_hex
  try {
    const out1 = await runLdbScan({
      dbPath: DB_PATH,
      cf: COLUMN_FAMILY,
      fromHex,
      toHex: toHexStr,
      useKeyHex: false,
    });
    const recs1 = parseLdb(out1);
    if (recs1.length) return groupResults(recs1);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("ldb (no --key_hex) failed:", (e as Error).message);
  }

  // Try ldb with --key_hex
  try {
    const out2 = await runLdbScan({
      dbPath: DB_PATH,
      cf: COLUMN_FAMILY,
      fromHex,
      toHex: toHexStr,
      useKeyHex: true,
    });
    const recs2 = parseLdb(out2);
    if (recs2.length) return groupResults(recs2);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("ldb (--key_hex) failed:", (e as Error).message);
  }

  // Fallback to sst_dump
  try {
    const out3 = await runSstDump({
      dbPath: DB_PATH,
      fromHex,
      toHex: toHexStr,
    });
    const recs3 = parseSstDump(out3);
    return groupResults(recs3);
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("sst_dump failed:", (e as Error).message);
    return { count: 0, records: [], bySuffix: {}, latestBySuffix: {} };
  }
}

// ---------- Express ----------
const app = express();
app.set("x-powered-by", false);

app.get("/health", (_req, res) => res.json({ ok: true }));

app.get("/dump/:alkaneId", async (req, res) => {
  try {
    const token = req.query.token as string | undefined;
    if (!AUTH_TOKEN || token !== AUTH_TOKEN) {
      return res.status(401).json({ error: "unauthorized" });
    }

    const alkaneId = req.params.alkaneId;
    if (!/^\d+:\d+$/.test(alkaneId)) {
      return res.status(400).json({ error: "invalid alkaneId, expected A:B" });
    }

    const endian =
      (req.query.endian as string) === "be" ? "be" : DEFAULT_ENDIAN;

    const result = await dumpAlkane(alkaneId, endian);
    return res.json({
      alkaneId,
      dbPath: DB_PATH,
      columnFamily: COLUMN_FAMILY,
      endian,
      ...result,
    });
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error(e);
    return res.status(500).json({ error: (e as Error).message });
  }
});

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`rocksdb-alkane-dump listening on :${PORT}`);
});

// ------------------------------
// package.json (example)
// ------------------------------
// {
//   "name": "alkane-dump-server",
//   "version": "0.1.0",
//   "type": "module",
//   "scripts": {
//     "build": "tsc -p tsconfig.json",
//     "start": "node dist/server.js",
//     "dev": "ts-node-esm server.ts"
//   },
//   "dependencies": {
//     "express": "^4.19.2"
//   },
//   "devDependencies": {
//     "@types/express": "^4.17.21",
//     "ts-node": "^10.9.2",
//     "typescript": "^5.5.4"
//   }
// }

// ------------------------------
// tsconfig.json (example)
// ------------------------------
// {
//   "compilerOptions": {
//     "target": "ES2022",
//     "module": "ES2022",
//     "moduleResolution": "bundler",
//     "lib": ["ES2022"],
//     "strict": true,
//     "esModuleInterop": true,
//     "skipLibCheck": true,
//     "outDir": "dist"
//   },
//   "include": ["server.ts"]
// }
