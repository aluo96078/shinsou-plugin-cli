/**
 * QuickJS (WASM, via quickjs-emscripten) engine for local hook tests. Runs the app's JavaScript
 * bridge bootstrap so scripts see the same `bridge.*`, `Jsoup`, `SManga`… surface.
 */

import { getQuickJS, shouldInterruptAfterDeadline, type QuickJSContext, type QuickJSHandle } from "quickjs-emscripten";
import { LEGACY_BOOTSTRAP } from "./legacy-bootstrap.ts";
import { DEFAULT_ENGINE_LIMITS, type BridgeHost, type EngineLimits, type InvokeOutcome, type SandboxEngine, type SandboxInstance } from "./sandbox.ts";

/** CLI additions: async `bridge.net.fetch` and a promise-aware invoke for async hooks. */
const CLI_BOOTSTRAP = `
(function(global){
  'use strict';
  bridge.net = {
    fetch: function(url, options){
      return __shinsouBridgeAsync('net.fetch', JSON.stringify([String(url), options || {}])).then(function(text){ return JSON.parse(text); });
    }
  };
  global.__cliInvoke = function(method, argsJson){
    if (typeof source !== 'object' || !source || typeof source[method] !== 'function') throw new Error('Plugin has no function ' + method);
    return Promise.resolve(source[method].apply(source, JSON.parse(argsJson || '[]'))).then(function(v){
      return JSON.stringify(v === undefined ? null : v);
    });
  };
})(this);
`;

export class QuickJsEngine implements SandboxEngine {
  readonly name = "quickjs-emscripten";

  async create(args: { script: string; sourceId: string | null; host: BridgeHost; limits?: EngineLimits }): Promise<SandboxInstance> {
    const QuickJS = await getQuickJS();
    const limits = args.limits ?? DEFAULT_ENGINE_LIMITS;
    const runtime = QuickJS.newRuntime();
    runtime.setMemoryLimit(limits.heapBytes);
    runtime.setMaxStackSize(limits.stackBytes);
    const ctx = runtime.newContext();
    const host = args.host;

    const bridgeFn = ctx.newFunction("__shinsouBridge", (opH, argsH) => {
      const outcome = host.call(ctx.getString(opH), ctx.getString(argsH));
      // The app's bootstrap turns every failure into `null` for the script.
      return ctx.newString(outcome.ok ? (outcome.json ?? "null") : "null");
    });
    ctx.setProp(ctx.global, "__shinsouBridge", bridgeFn);
    bridgeFn.dispose();

    const asyncFn = ctx.newFunction("__shinsouBridgeAsync", (opH, argsH) => {
      const deferred = ctx.newPromise();
      host.callAsync(ctx.getString(opH), ctx.getString(argsH)).then(
        (outcome) => {
          if (!ctx.alive) return;
          if (outcome.ok) {
            const s = ctx.newString(outcome.json ?? "null");
            deferred.resolve(s);
            s.dispose();
          } else {
            const e = ctx.newError(`bridge error ${outcome.code}`);
            deferred.reject(e);
            e.dispose();
          }
          runtime.executePendingJobs();
        },
        () => {
          if (!ctx.alive) return;
          const e = ctx.newError("bridge host failure");
          deferred.reject(e);
          e.dispose();
          runtime.executePendingJobs();
        },
      );
      return deferred.handle;
    });
    ctx.setProp(ctx.global, "__shinsouBridgeAsync", asyncFn);
    asyncFn.dispose();

    const evalOrThrow = (code: string, filename: string) => {
      runtime.setInterruptHandler(shouldInterruptAfterDeadline(Date.now() + limits.invokeTimeoutMs));
      const r = ctx.evalCode(code, filename);
      if (r.error) {
        const message = describe(ctx, r.error);
        r.error.dispose();
        throw new Error(`${filename}: ${message}`);
      }
      r.value.dispose();
    };
    try {
      evalOrThrow(LEGACY_BOOTSTRAP, "bootstrap.js");
      evalOrThrow(CLI_BOOTSTRAP, "cli-bootstrap.js");
      evalOrThrow(args.script, "plugin.js");
      evalOrThrow(`__shinsouSelectSource(${JSON.stringify(args.sourceId)})`, "select-source.js");
    } catch (err) {
      ctx.dispose();
      runtime.dispose();
      throw err;
    }

    return {
      async invoke(method: string, argsJson: string): Promise<InvokeOutcome> {
        const deadline = Date.now() + limits.invokeTimeoutMs;
        runtime.setInterruptHandler(shouldInterruptAfterDeadline(deadline));
        const fn = ctx.getProp(ctx.global, "__cliInvoke");
        const m = ctx.newString(method);
        const a = ctx.newString(argsJson);
        const r = ctx.callFunction(fn, ctx.undefined, m, a);
        fn.dispose();
        m.dispose();
        a.dispose();
        if (r.error) {
          const error = describe(ctx, r.error);
          r.error.dispose();
          return { ok: false, error };
        }
        const promise = r.value;
        const settled = ctx.resolvePromise(promise);
        promise.dispose();
        let done = false;
        settled.finally(() => (done = true));
        while (!done) {
          const jobs = runtime.executePendingJobs();
          if (jobs.error) {
            const error = describe(ctx, jobs.error);
            jobs.error.dispose();
            return { ok: false, error };
          }
          if (Date.now() > deadline) return { ok: false, error: "invocation timed out", limit: "TIME" };
          await new Promise((resolve) => setImmediate(resolve));
        }
        const result = await settled;
        if (result.error) {
          const error = describe(ctx, result.error);
          result.error.dispose();
          return { ok: false, error };
        }
        const valueJson = ctx.getString(result.value);
        result.value.dispose();
        return { ok: true, valueJson };
      },
      dispose() {
        ctx.dispose();
        runtime.dispose();
      },
    };
  }
}

function describe(ctx: QuickJSContext, handle: QuickJSHandle): string {
  const v = ctx.dump(handle) as unknown;
  if (v && typeof v === "object") {
    const e = v as { name?: string; message?: string; stack?: string };
    return [e.name && e.message ? `${e.name}: ${e.message}` : e.message ?? JSON.stringify(v), e.stack].filter(Boolean).join("\n");
  }
  return String(v);
}
