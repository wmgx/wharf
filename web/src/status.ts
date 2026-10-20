import { createContext, useContext } from "react";
import type { Status } from "./types";

interface StatusCtx {
  status: Status | null;
  refresh: () => void;
}

export const StatusContext = createContext<StatusCtx>({ status: null, refresh: () => {} });

/** 全局状态：每 5 秒拉一次 /api/status，各页面共用。 */
export const useStatus = () => useContext(StatusContext);
