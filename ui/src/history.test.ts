import { describe, expect, it } from 'vitest';
import { history, recordStatus, stateSince } from './history';
import { attackStatus } from './test/helpers';

const at = (allow: number, drop = 0) => ({ ...attackStatus, requests: { ...attackStatus.requests, allow, drop } });

describe('history', () => {
  it('turns counters into rates', () => {
    recordStatus(at(100, 0), 0);
    recordStatus(at(300, 100), 2000);
    expect(history()).toHaveLength(1);
    expect(history()[0]?.allow).toBe(100);
    expect(history()[0]?.drop).toBe(50);
  });
  it('resets when a counter goes down (restart)', () => {
    recordStatus(at(100), 0);
    recordStatus(at(300), 2000);
    recordStatus(at(5), 4000);
    expect(history()).toHaveLength(0);
    recordStatus(at(25), 6000);
    expect(history()[0]?.allow).toBe(10);
  });
  it('drops samples older than 15 minutes', () => {
    recordStatus(at(0), 0);
    recordStatus(at(10), 2000);
    recordStatus(at(20), 2000 + 16 * 60_000);
    expect(history()).toHaveLength(1);
  });
  it('tracks when the state was first seen', () => {
    recordStatus(attackStatus, 1000);
    recordStatus(attackStatus, 9000);
    expect(stateSince()).toEqual({ state: 'attack', at: 1000 });
    recordStatus({ ...attackStatus, detection: 'cooldown' }, 10_000);
    expect(stateSince()).toEqual({ state: 'cooldown', at: 10_000 });
  });
});
