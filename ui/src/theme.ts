import { createSignal } from 'solid-js';

export type ThemePref = 'system' | 'light' | 'dark';
const KEY = 'dvarapala-theme';

export function loadPref(): ThemePref {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'light' || v === 'dark' || v === 'system') return v;
  } catch {
    // storage blocked: fall back to the system theme
  }
  return 'system';
}

export function savePref(pref: ThemePref): void {
  try {
    localStorage.setItem(KEY, pref);
  } catch {
    // storage blocked: the choice lasts for this page only
  }
}

function systemTheme(): 'light' | 'dark' {
  return typeof matchMedia === 'function' && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

/** Put the resolved theme on <html data-theme>. */
export function applyTheme(pref: ThemePref): void {
  document.documentElement.setAttribute('data-theme', pref === 'system' ? systemTheme() : pref);
}

const [themePref, setPref] = createSignal<ThemePref>(loadPref());
export { themePref };

/** Choose a theme: remember it (best effort) and put it on <html>. */
export function setThemePref(pref: ThemePref): void {
  setPref(pref);
  savePref(pref);
  applyTheme(pref);
}

/** Apply the saved choice now and follow the OS theme while it is "system". */
export function initTheme(): void {
  applyTheme(themePref());
  if (typeof matchMedia !== 'function') return;
  matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    if (themePref() === 'system') applyTheme('system');
  });
}
