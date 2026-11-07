/**
 * `serve`: an unsigned developer repository over plain HTTP on loopback or a LAN address, rebuilt
 * whenever the project changes. The app only loads it in plugin developer mode (ADR-0002 §8.1).
 */

import { existsSync, readFileSync, statSync, watch } from "node:fs";
import { createServer, type Server } from "node:http";
import { isIP } from "node:net";
import { networkInterfaces } from "node:os";
import { join, normalize, relative, sep } from "node:path";
import { buildProject, DEFAULT_OUT_DIR, type BuildResult } from "../core/build.ts";

export function isPrivateIPv4(ip: string): boolean {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254);
}

export function localLanAddresses(): string[] {
  return Object.values(networkInterfaces())
    .flat()
    .filter((i): i is NonNullable<typeof i> => !!i && i.family === "IPv4" && !i.internal && isPrivateIPv4(i.address))
    .map((i) => i.address);
}

/** Loopback, or a private LAN address that belongs to this machine. Never 0.0.0.0 or public IPs. */
export function resolveServeHost(host: string): string {
  if (host === "127.0.0.1" || host === "localhost") return "127.0.0.1";
  if (host === "::1") return "::1";
  if (host === "lan") {
    const lan = localLanAddresses();
    if (!lan.length) throw new Error("找不到區域網路 IPv4 位址；請改用 --host <IP>");
    return lan[0];
  }
  if (isIP(host) !== 4 || !isPrivateIPv4(host)) {
    throw new Error(`--host 只接受 127.0.0.1、::1 或本機的私有區域網路 IPv4 位址（10/8、172.16/12、192.168/16），收到 ${host}`);
  }
  if (!localLanAddresses().includes(host)) throw new Error(`${host} 不是這台電腦的網路介面位址`);
  return host;
}

export function devRepositoryLink(baseUrl: string): string {
  return `shinsou://add-dev-repository?url=${encodeURIComponent(baseUrl)}`;
}

const CONTENT_TYPES: Record<string, string> = {
  ".json": "application/json; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".png": "image/png",
  ".webp": "image/webp",
};

export async function serveProject(args: {
  projectDir: string;
  host: string;
  port: number;
  onEvent?: (msg: string) => void;
  watchFiles?: boolean;
}): Promise<{ server: Server; baseUrl: string; link: string; close: () => Promise<void> }> {
  const log = args.onEvent ?? ((m: string) => console.log(m));
  const host = resolveServeHost(args.host);
  const root = join(args.projectDir, DEFAULT_OUT_DIR);
  let revision = 0;
  let last: BuildResult | null = null;
  let lastError: string | null = null;

  const rebuild = async () => {
    try {
      last = await buildProject(args.projectDir);
      revision++;
      lastError = null;
      log(`[build #${revision}] ${last.manifest.packageId} ${last.manifest.version} sha256=${last.sha256.slice(0, 12)}… ${last.byteSize} bytes`);
    } catch (err) {
      lastError = (err as Error).message;
      log(`[build 失敗，繼續提供上一個版本] ${lastError}`);
    }
  };
  await rebuild();

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://dev.invalid");
    res.setHeader("Cache-Control", "no-store");
    if (url.pathname === "/__shinsou-dev/status") {
      res.setHeader("Content-Type", "application/json; charset=utf-8");
      res.end(JSON.stringify({ revision, ok: lastError === null, error: lastError, sha256: last?.sha256 ?? null, packageId: last?.manifest.packageId ?? null }));
      return;
    }
    let rel: string;
    try {
      rel = normalize(decodeURIComponent(url.pathname)).replace(/^[/\\]+/, "");
    } catch {
      res.statusCode = 400;
      res.end();
      return;
    }
    const file = join(root, rel || "index.json");
    const inside = relative(root, file);
    if (inside.startsWith("..") || inside.split(sep).includes("..") || !existsSync(file) || !statSync(file).isFile()) {
      res.statusCode = 404;
      res.end("not found");
      return;
    }
    const ext = file.slice(file.lastIndexOf("."));
    res.setHeader("Content-Type", CONTENT_TYPES[ext] ?? "application/octet-stream");
    res.end(readFileSync(file));
    log(`${req.method} ${url.pathname}`);
  });
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(args.port, host, () => resolveListen());
  });
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : args.port;
  const baseUrl = `http://${host.includes(":") ? `[${host}]` : host}:${port}`;

  let watcher: ReturnType<typeof watch> | null = null;
  if (args.watchFiles !== false) {
    let timer: NodeJS.Timeout | null = null;
    const ignored = /^(build|public|node_modules|\.git|\.shinsou)([/\\]|$)/;
    watcher = watch(args.projectDir, { recursive: true }, (_event, filename) => {
      if (!filename || ignored.test(String(filename))) return;
      if (timer) clearTimeout(timer);
      timer = setTimeout(() => void rebuild(), 150);
    });
  }
  return {
    server,
    baseUrl,
    link: devRepositoryLink(baseUrl),
    close: () =>
      new Promise((r) => {
        watcher?.close();
        server.close(() => r());
      }),
  };
}
