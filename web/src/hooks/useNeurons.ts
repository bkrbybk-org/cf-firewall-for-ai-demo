import { useCallback, useEffect, useRef, useState } from "react";
import { getNeurons } from "../lib/api";
import type { Neurons } from "../lib/types";

const REFRESH_MS = 300000; // 5 min

export interface NeuronState {
  data: Neurons | null;
  fetchedAt: string | null;
}

// Fetches account Neuron usage on mount, every 5 min, and via refresh().
export function useNeurons() {
  const [state, setState] = useState<NeuronState>({ data: null, fetchedAt: null });
  const timer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      const data = await getNeurons();
      setState({ data, fetchedAt: new Date().toLocaleTimeString("en-GB", { hour12: false }) });
    } catch {
      /* keep last value on transient errors */
    }
  }, []);

  useEffect(() => {
    refresh();
    timer.current = window.setInterval(refresh, REFRESH_MS);
    return () => {
      if (timer.current) window.clearInterval(timer.current);
    };
  }, [refresh]);

  return { state, refresh };
}
