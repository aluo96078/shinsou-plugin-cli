/**
 * The engine boundary used by `shinsou-plugin test`. It mirrors SandboxProtocol v1 semantics
 * (INIT → READY, INVOKE → RESULT/FAILURE, BRIDGE_CALL ↔ BRIDGE_RESULT, ASYNC_BRIDGE_CALL ↔
 * ASYNC_BRIDGE_RESULT) so the QuickJS implementation can be swapped for the app's own guest.
 *
 * TODO(sandbox-core): add a `SandboxCoreWasmEngine` that loads the app's sandbox-core WASM guest and
 * talks to it with the frames in src/core/sandbox-protocol.ts, then make it the default engine.
 */

export type BridgeOutcome = { ok: true; json: string | null } | { ok: false; code: number };

export interface BridgeHost {
  /** Synchronous bridge call (BRIDGE_CALL); `argsJson` is a JSON array. */
  call(op: string, argsJson: string): BridgeOutcome;
  /** Asynchronous bridge call (ASYNC_BRIDGE_CALL); protocol v1 only defines `net.fetch`. */
  callAsync(op: string, argsJson: string): Promise<BridgeOutcome>;
  log(message: string): void;
}

export interface EngineLimits {
  heapBytes: number;
  stackBytes: number;
  invokeTimeoutMs: number;
}

export const DEFAULT_ENGINE_LIMITS: EngineLimits = {
  heapBytes: 64 << 20,
  stackBytes: 1 << 20,
  invokeTimeoutMs: 30_000,
};

export type InvokeOutcome = { ok: true; valueJson: string } | { ok: false; error: string; limit?: string };

export interface SandboxInstance {
  invoke(method: string, argsJson: string): Promise<InvokeOutcome>;
  dispose(): void;
}

export interface SandboxEngine {
  readonly name: string;
  /** INIT: evaluates [script] and selects [sourceId] (exact id, never position). */
  create(args: { script: string; sourceId: string | null; host: BridgeHost; limits?: EngineLimits }): Promise<SandboxInstance>;
}
