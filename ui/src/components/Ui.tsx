import { createEffect, on, type JSX } from 'solid-js';
import { fmtInt } from '../format';

/** A number that flashes when it changes. */
export function Num(props: { value: number; fmt?: (n: number) => string }) {
  let el!: HTMLSpanElement;
  createEffect(
    on(
      () => props.value,
      () => {
        el.classList.remove('flash');
        void el.offsetWidth;
        el.classList.add('flash');
      },
      { defer: true },
    ),
  );
  return (
    <span ref={el} class="num rounded">
      {(props.fmt ?? fmtInt)(props.value)}
    </span>
  );
}

export function PageHeader(props: { title: string; children?: JSX.Element }) {
  return (
    <div class="mb-4 flex flex-wrap items-center justify-between gap-2">
      <h1 class="text-xl font-semibold tracking-tight">{props.title}</h1>
      {props.children}
    </div>
  );
}

export function Unavailable(props: { what: string; message: string }) {
  return (
    <div class="empty" role="status">
      <p class="font-medium">{props.what} is not available</p>
      <p class="text-muted">{props.message}</p>
      <p class="text-muted">
        The rate limiter is off (<code class="font-mono">l7.rate_limit</code> not set) or the gateway runs in forward mode. Overview still works.
      </p>
    </div>
  );
}
