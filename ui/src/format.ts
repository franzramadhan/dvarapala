export function fmtInt(n: number): string {
  return Math.round(n).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export function fmtRate(n: number): string {
  if (n >= 100) return fmtInt(n);
  if (n >= 10) return n.toFixed(1);
  return n.toFixed(2);
}

/** 90 -> "1m 30s", 3700 -> "1h 01m", 90000 -> "1d 1h". */
export function fmtDuration(totalSecs: number): string {
  const s = Math.max(0, Math.floor(totalSecs));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${String(s % 60).padStart(2, '0')}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${String(m % 60).padStart(2, '0')}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function fmtClock(unixSecs: number): string {
  return new Date(unixSecs * 1000).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

const UNIT: Record<string, number> = { s: 1, m: 60, h: 3600, d: 86400 };

/** "10m" -> 600; null when not of the form <digits><s|m|h|d> or zero. */
export function parseTtl(input: string): number | null {
  const m = /^(\d{1,9})([smhd])$/.exec(input.trim());
  if (!m) return null;
  const secs = Number(m[1]) * (UNIT[m[2] as string] as number);
  return secs > 0 ? secs : null;
}
