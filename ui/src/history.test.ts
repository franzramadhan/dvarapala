import { describe, expect, it } from 'vitest';
import { history, historyGap, recordStatus, seedHistory, stateSince, type Sample } from './history';
import { attackStatus } from './test/helpers';

const sample = (t: number, allow: number): Sample => ({ t, allow, throttle: 0, challenge: 0, drop: 0, error: 0 });
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
  it('does not average a gap into one sample (hidden tab)', () => {
    const gaps = historyGap();
    recordStatus(at(0), 0);
    recordStatus(at(0), 2000);
    recordStatus(at(600), 62_000);
    expect(history().map((s) => s.t)).toEqual([2000]);
    expect(historyGap()).toBe(gaps + 1);
    recordStatus(at(610), 64_000);
    expect(history().map((s) => s.allow)).toEqual([0, 5]);
  });
  it('fills a gap with the gateway samples', () => {
    recordStatus(at(0), 0);
    recordStatus(at(0), 2000);
    recordStatus(at(600), 62_000);
    // the refetch answers before the next poll closes the gap
    seedHistory([sample(-5000, 1), sample(1000, 1), sample(30_000, 10), sample(61_000, 9)]);
    recordStatus(at(610), 64_000);
    expect(history().map((s) => s.t)).toEqual([-5000, 1000, 2000, 30_000, 61_000, 64_000]);
    // a later seed fills a closed gap and keeps the samples it already has
    seedHistory([sample(45_000, 10), sample(61_000, 9)]);
    expect(history().map((s) => s.t)).toEqual([-5000, 1000, 2000, 30_000, 45_000, 61_000, 64_000]);
  });
});
