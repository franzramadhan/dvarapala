export type CidrInfo = {
  family: 4 | 6;
  prefix: number;
  /** Exponent n: the range holds 2^n addresses. */
  hostBits: number;
  /** Human text such as "65,536 addresses" or "2^64 addresses". */
  size: string;
  /** True for ranges large enough to cut off a lot of legitimate traffic. */
  huge: boolean;
};

export function groupDigits(n: bigint): string {
  return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

function validIpv4(s: string): boolean {
  const parts = s.split('.');
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255);
}

function validIpv6(s: string): boolean {
  if (!/^[0-9a-fA-F:.]+$/.test(s) || s.includes(':::')) return false;
  const dbl = s.split('::');
  if (dbl.length > 2) return false;
  let groups = 0;
  for (const side of dbl) {
    if (side === '') continue;
    const parts = side.split(':');
    for (let i = 0; i < parts.length; i++) {
      const p = parts[i] as string;
      const last = i === parts.length - 1 && side === (dbl[dbl.length - 1] as string);
      if (last && p.includes('.')) {
        if (!validIpv4(p)) return false;
        groups += 2;
      } else if (/^[0-9a-fA-F]{1,4}$/.test(p)) {
        groups += 1;
      } else {
        return false;
      }
    }
  }
  return dbl.length === 2 ? groups < 8 : groups === 8;
}

/**
 * Parse an IPv4 or IPv6 network ("192.0.2.0/24", "2001:db8::/32") or a bare
 * address (a single host). Returns null when it is not valid.
 */
export function parseCidr(input: string): CidrInfo | null {
  const s = input.trim();
  if (s === '') return null;
  const [addr = '', pfx, ...rest] = s.split('/');
  if (rest.length) return null;
  const family = addr.includes(':') ? 6 : 4;
  const max = family === 4 ? 32 : 128;
  if (family === 4 ? !validIpv4(addr) : !validIpv6(addr)) return null;
  let prefix = max;
  if (pfx !== undefined) {
    if (!/^\d{1,3}$/.test(pfx)) return null;
    prefix = Number(pfx);
    if (prefix > max) return null;
  }
  const hostBits = max - prefix;
  let size: string;
  if (family === 4) {
    const count = 1n << BigInt(hostBits);
    size = `${groupDigits(count)} ${count === 1n ? 'address' : 'addresses'}`;
  } else {
    size = hostBits === 0 ? '1 address' : hostBits <= 20 ? `${groupDigits(1n << BigInt(hostBits))} addresses` : `2^${hostBits} addresses`;
  }
  const huge = family === 4 ? prefix <= 8 : prefix <= 32;
  return { family, prefix, hostBits, size, huge };
}

/** Sentence for the add-block form. */
export function blockImpact(info: CidrInfo): string {
  return info.size.startsWith('1 ') ? 'this blocks 1 address' : `this blocks ${info.size}`;
}
