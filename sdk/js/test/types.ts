// RFC 0008 case 12: `tsc --noEmit` on the public types.
import { Guard, type Verdict } from '..';

const g = new Guard({ 'rate_limit.rate': 20, trusted_proxies: ['192.0.2.0/24'], 'l4.enabled': true });
const v: Verdict = g.check('192.0.2.1', null);
const kind: 'allow' | 'throttle' | 'drop' = v.kind;
const n: number = g.stats().clients + v.retryAfterMs;
g.connOpen('192.0.2.1').close();
const mw = g.middleware();
mw({ headers: {}, socket: { remoteAddress: '192.0.2.1' } }, { writeHead: () => 0, end: () => 0 }, () => {});
// @ts-expect-error: settings are strings, numbers, booleans or lists
new Guard({ rate: {} });
export { kind, n };
