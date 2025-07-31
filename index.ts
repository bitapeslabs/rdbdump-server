// server.ts
// Express server that exposes an authenticated endpoint to dump Alkane storage
// from a RocksDB directory using ldb / sst_dump and returns structured JSON.
//
// Endpoint:
//   GET /dump/:alkaneId?token=YOUR_TOKEN
//
// ---------------------------------------------------------------------------
// ENV VARS
//   DB_PATH           – RocksDB dir (default /data/.metashrew/mainnet)
//   AUTH_TOKEN        – required auth token
//   LDB_BIN           – path to ldb        (default "ldb")
//   SST_DUMP_BIN      – path to sst_dump   (default "sst_dump")
//   COLUMN_FAMILY     – RocksDB CF         (default "default")
//   ENDIAN            – le | be            (default "le")
//   PORT              – server port        (default 7107)
//   CHILD_TIMEOUT_MS  – per-process limit  (default 120 000 ms)
// ---------------------------------------------------------------------------
// CHANGELOG
// • 2025-07-31 – added `contractKeyHex` per record.
// ---------------------------------------------------------------------------

import express from "express";
import { spawn } from "child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import "dotenv/config";

/* ───── config ───── */
const DB_PATH = process.env.DB_PATH ?? "/data/.metashrew/mainnet";
const AUTH_TOKEN = process.env.AUTH_TOKEN ?? "";
const LDB_BIN = process.env.LDB_BIN ?? "ldb";
const SST_DUMP_BIN = process.env.SST_DUMP_BIN ?? "sst_dump";
const COLUMN_FAMILY = process.env.COLUMN_FAMILY ?? "default";
const DEFAULT_ENDIAN =
  (process.env.ENDIAN as "le" | "be") === "be" ? "be" : "le";
const PORT = Number(process.env.PORT ?? 7107);
const CHILD_TIMEOUT = Number(process.env.CHILD_TIMEOUT_MS ?? 120_000);

if (!AUTH_TOKEN)
  console.warn("[WARN] AUTH_TOKEN is empty – endpoint is public!");

/* ───── helpers ───── */
const toHex = (b: Buffer) => "0x" + b.toString("hex");
const fromHex = (h: string) => Buffer.from(h.replace(/^0x/i, ""), "hex");
const isPrint = (b: Buffer) =>
  b.length && [...b].every((v) => v >= 0x20 && v < 0x7f);
const toAscii = (b: Buffer) => b.toString("utf8");
const pretty = (b: Buffer) =>
  [...b]
    .map((c) =>
      c >= 0x20 && c < 0x7f
        ? String.fromCharCode(c)
        : `\\x${c.toString(16).padStart(2, "0")}`
    )
    .join("");

function u128le(n: bigint) {
  const b = Buffer.alloc(16);
  for (let i = 0; i < 16; i++) {
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return b;
}
function u128be(n: bigint) {
  const b = Buffer.alloc(16);
  for (let i = 15; i >= 0; i--) {
    b[i] = Number(n & 0xffn);
    n >>= 8n;
  }
  return b;
}

function parseAlkaneId(str: string): [bigint, bigint] {
  const m = str.match(/^(\d+):(\d+)$/);
  if (!m) throw new Error("AlkaneId must be A:B (decimal u128)");
  return [BigInt(m[1]), BigInt(m[2])];
}
function makePrefix(id: string, endian: "le" | "be") {
  const [a, b] = parseAlkaneId(id);
  const enc = endian === "be" ? u128be : u128le;
  return Buffer.concat([
    Buffer.from("/alkanes/"),
    enc(a),
    enc(b),
    Buffer.from("/storage"),
  ]);
}

function normalizeSuffix(ascii: string) {
  const i = ascii.indexOf("/storage");
  let s = i >= 0 ? ascii.slice(i + "/storage".length) : ascii;
  if (s.startsWith("//")) s = s.slice(1);
  if (!s.startsWith("/")) s = "/" + s;
  return s;
}

/** Extract on-chain bytes (after “/storage”), trim dup “/”, drop “/length”. */
function extractContractKeyHex(kbuf: Buffer): string {
  const marker = Buffer.from("/storage");
  const i = kbuf.indexOf(marker);
  if (i === -1) return toHex(kbuf); // fallback

  let tail = kbuf.slice(i + marker.length); // bytes after '/storage'

  if (tail[0] === 0x2f && tail[1] === 0x2f) tail = tail.slice(1); // remove extra '/'
  const lenTag = Buffer.from("/length");
  if (tail.slice(-lenTag.length).equals(lenTag))
    tail = tail.slice(0, -lenTag.length);

  return toHex(tail);
}

function decodeVal(buf: Buffer) {
  if (isPrint(buf)) {
    const text = toAscii(buf);
    const m = text.match(/^(\d+):([0-9a-fA-F]+)0*$/);
    if (m) return { text, block: Number(m[1]), hex: m[2].toLowerCase() };
    return { text };
  }
  return { hex: toHex(buf) };
}

/* ───── parsers ───── */
const KV_RE = /(0x[0-9a-fA-F]+)\s*={1,2}>\s*(0x[0-9a-fA-F]+)/; // '=>' or '==>'

const parseLdb = (out: string) =>
  out.split(/\r?\n/).flatMap((l) => {
    const m = l.match(KV_RE);
    return m ? [{ kbuf: fromHex(m[1]), vbuf: fromHex(m[2]) }] : [];
  });

const parseSst = (out: string) => {
  const re = /^0x([0-9a-fA-F]+)\s+@\s+\d+:\s+\d+\s+={1,2}>\s+0x([0-9a-fA-F]+)$/;
  return out.split(/\r?\n/).flatMap((l) => {
    const m = l.match(re);
    return m
      ? [{ kbuf: Buffer.from(m[1], "hex"), vbuf: Buffer.from(m[2], "hex") }]
      : [];
  });
};

/* ───── child ───── */
function run(cmd: string, args: string[]) {
  return new Promise<string>((res, rej) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "",
      err = "";
    const t = setTimeout(() => {
      p.kill("SIGKILL");
      rej(new Error("timeout"));
    }, CHILD_TIMEOUT);
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (err += d));
    p.on("error", rej);
    p.on("close", (c) => {
      clearTimeout(t);
      c === 0 ? res(out) : rej(new Error(`${cmd}=>${c}: ${err}`));
    });
  });
}

/* ───── dump core ───── */
async function dump(id: string, endian: "le" | "be") {
  const pref = makePrefix(id, endian);
  const from = toHex(pref);
  const to = toHex(Buffer.concat([pref, Buffer.from([0xff])]));

  const sec = fs.mkdtempSync(path.join(os.tmpdir(), "ldb_sec_"));
  const ldbArgs = (keyHex: boolean) => [
    `--db=${DB_PATH}`,
    `--secondary_path=${sec}`,
    `--try_load_options`,
    `--column_family=${COLUMN_FAMILY}`,
    "scan",
    ...(keyHex ? ["--key_hex"] : []),
    `--from=${from}`,
    `--to=${to}`,
    "--hex",
  ];

  try {
    const o1 = await run(LDB_BIN, ldbArgs(false));
    const r1 = parseLdb(o1);
    if (r1.length) return r1;
  } catch {}
  try {
    const o2 = await run(LDB_BIN, ldbArgs(true));
    const r2 = parseLdb(o2);
    if (r2.length) return r2;
  } catch {}

  const sstArgs = [
    `--file=${DB_PATH}`,
    "--command=scan",
    `--from=${from}`,
    `--to=${to}`,
    "--input_key_hex",
    "--output_hex",
  ];
  const o3 = await run(SST_DUMP_BIN, sstArgs);
  return parseSst(o3);
}

function aggregate(rows: { kbuf: Buffer; vbuf: Buffer }[]) {
  const records: any[] = [];
  const by: Record<string, any[]> = {};
  const latest: Record<string, any> = {};

  for (const { kbuf, vbuf } of rows) {
    const suffix = normalizeSuffix(toAscii(kbuf));
    const val = decodeVal(vbuf);

    records.push({
      key: suffix,
      contractKeyHex: extractContractKeyHex(kbuf),
      rawKey: { ascii: pretty(kbuf), hex: toHex(kbuf) },
      value: val,
      valueHex: toHex(vbuf),
    });

    (by[suffix] ??= []).push(val);
    if (typeof val.block === "number") {
      if (!latest[suffix] || val.block > latest[suffix].block)
        latest[suffix] = val;
    }
  }
  return {
    count: records.length,
    records,
    bySuffix: by,
    latestBySuffix: latest,
  };
}

/* ───── express ───── */
const app = express();
app.set("x-powered-by", false);

app.get("/health", (_, res) => res.json({ ok: true }));

app.get("/dump/:alkaneId", async (req, res) => {
  if (!AUTH_TOKEN || req.query.token !== AUTH_TOKEN)
    return res.status(401).json({ error: "unauthorized" });

  const id = req.params.alkaneId;
  if (!/^\d+:\d+$/.test(id))
    return res.status(400).json({ error: "invalid alkaneId (A:B)" });

  try {
    const endian =
      (req.query.endian as string) === "be" ? "be" : DEFAULT_ENDIAN;
    const raw = await dump(id, endian);
    const agg = aggregate(raw);
    return res.json({
      alkaneId: id,
      dbPath: DB_PATH,
      columnFamily: COLUMN_FAMILY,
      endian,
      ...agg,
    });
  } catch (e: any) {
    console.error(e);
    return res.status(500).json({ error: e.message });
  }
});

app.listen(PORT, () => console.log(`alkane-dump listening on :${PORT}`));
