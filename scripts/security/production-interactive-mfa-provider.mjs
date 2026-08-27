import { spawnSync } from "node:child_process";
import { closeSync, openSync } from "node:fs";

const MFA_CODE = /^[0-9]{6,8}$/;

const promptIsSafe = (prompt) => typeof prompt === "string" && prompt.length > 0 && !/[\r\n\0]/.test(prompt);

/** Reads one validated value from the controlling terminal without echoing it. */
export function promptProductionHiddenInput({ prompt, validate = (value) => Boolean(value), errorMessage = "Interactive input failed.", openTerminal = openSync, closeTerminal = closeSync, spawn = spawnSync } = {}) {
  if (!promptIsSafe(prompt) || typeof validate !== "function" || typeof errorMessage !== "string" || typeof openTerminal !== "function" || typeof closeTerminal !== "function" || typeof spawn !== "function") throw new Error("Interactive input provider configuration is invalid.");
  let terminal;
  let output = Buffer.alloc(0);
  try {
    terminal = openTerminal("/dev/tty", "r+");
    const result = spawn("/bin/sh", ["-c", "restore(){ stty echo <&0 >/dev/null 2>&1 || true; }; trap 'restore' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM; printf '%s' \"$1\" >&0; stty -echo <&0 || exit 1; IFS= read -r value <&0 || exit 1; printf '\\n' >&0; printf '%s' \"$value\"", "sh", prompt], { encoding: null, env: { PATH: "/usr/bin:/bin" }, stdio: [terminal, "pipe", "ignore"] });
    output = Buffer.isBuffer(result?.stdout) ? result.stdout : Buffer.from(result?.stdout || "");
    const value = output.toString("utf8").trim();
    if (result?.error || result?.status !== 0 || !validate(value)) throw new Error(errorMessage);
    return value;
  } finally {
    output.fill(0);
    if (terminal !== undefined) closeTerminal(terminal);
  }
}

/**
 * Reads a one-time MFA code only from the controlling terminal. The shell owns
 * echo restoration so HUP/INT/TERM restore the TTY even if Node is interrupted.
 */
export function promptProductionMfaCode({ prompt, openTerminal = openSync, closeTerminal = closeSync, spawn = spawnSync } = {}) {
  return promptProductionHiddenInput({ prompt, validate: (code) => MFA_CODE.test(code), errorMessage: "Interactive MFA entry failed.", openTerminal, closeTerminal, spawn });
}
