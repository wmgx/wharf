import { useSearchParams } from "react-router-dom";

/** 页面标签记在地址的 `tab` 参数里：刷新、分享、从别处跳过来都能落到同一个标签。 */
export function useTab<T extends string>(tabs: readonly T[], fallback: T): [T, (t: T) => void] {
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const tab = tabs.includes(raw as T) ? (raw as T) : fallback;
  const set = (t: T) => setParams(t === fallback ? {} : { tab: t });
  return [tab, set];
}
