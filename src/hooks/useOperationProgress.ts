import { useCallback, useEffect, useRef, useState } from "react";

export type OperationProgressState = {
  open: boolean;
  title: string;
  description: string;
  phaseLabel: string;
  detail: string;
  speedLabel: string;
  value: number;
  indeterminate: boolean;
};

type StartOptions = {
  title: string;
  description: string;
  phaseLabel?: string;
  detail?: string;
  initialValue?: number;
  mode?: "simulated" | "determinate";
  tickMs?: number;
  maxValue?: number;
};

type UpdateOptions = {
  value?: number;
  detail?: string;
  speedLabel?: string;
  phaseLabel?: string;
  indeterminate?: boolean;
};

const clamp = (n: number, min = 0, max = 100) => Math.min(max, Math.max(min, n));

const DEFAULT_STATE: OperationProgressState = {
  open: false,
  title: "",
  description: "",
  phaseLabel: "",
  detail: "",
  speedLabel: "",
  value: 0,
  indeterminate: true,
};

export const useOperationProgress = () => {
  const [state, setState] = useState<OperationProgressState>(DEFAULT_STATE);
  const timerRef = useRef<number | null>(null);

  const clearTimer = useCallback(() => {
    if (timerRef.current != null) {
      window.clearInterval(timerRef.current);
      timerRef.current = null;
    }
  }, []);

  const close = useCallback(() => {
    clearTimer();
    setState(DEFAULT_STATE);
  }, [clearTimer]);

  const start = useCallback(
    (opts: StartOptions) => {
      clearTimer();
      const initialValue = clamp(opts.initialValue ?? 8);
      const maxValue = clamp(opts.maxValue ?? 92);
      const tickMs = Math.max(200, opts.tickMs ?? 380);
      const mode = opts.mode || "simulated";

      setState({
        open: true,
        title: opts.title,
        description: opts.description,
        phaseLabel: opts.phaseLabel || "In progress",
        detail: opts.detail || "",
        speedLabel: "",
        value: initialValue,
        indeterminate: mode === "simulated",
      });

      if (mode !== "simulated") return;

      timerRef.current = window.setInterval(() => {
        setState((prev) => {
          if (!prev.open) return prev;
          if (prev.value >= maxValue) return prev;
          const step = prev.value < 45 ? 4 : prev.value < 70 ? 2 : 1;
          return { ...prev, value: clamp(prev.value + step, 0, maxValue), indeterminate: true };
        });
      }, tickMs);
    },
    [clearTimer]
  );

  const update = useCallback((opts: UpdateOptions) => {
    setState((prev) => {
      if (!prev.open) return prev;
      return {
        ...prev,
        value: opts.value == null ? prev.value : clamp(opts.value),
        detail: opts.detail ?? prev.detail,
        speedLabel: opts.speedLabel ?? prev.speedLabel,
        phaseLabel: opts.phaseLabel ?? prev.phaseLabel,
        indeterminate: opts.indeterminate ?? prev.indeterminate,
      };
    });
  }, []);

  const complete = useCallback(
    async (detail?: string) => {
      clearTimer();
      setState((prev) => {
        if (!prev.open) return prev;
        return {
          ...prev,
          value: 100,
          indeterminate: false,
          speedLabel: "",
          detail: detail ?? prev.detail,
          phaseLabel: "Finalizing",
        };
      });
      await new Promise((resolve) => window.setTimeout(resolve, 320));
      setState(DEFAULT_STATE);
    },
    [clearTimer]
  );

  useEffect(() => {
    return () => {
      clearTimer();
    };
  }, [clearTimer]);

  return { state, start, update, complete, close };
};

