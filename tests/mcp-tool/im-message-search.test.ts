import { mapWithConcurrency } from '../../src/mcp-tool/tools/en/builtin-tools/im/message-search';

describe('mapWithConcurrency', () => {
  it('preserves input order even when workers finish out of order', async () => {
    const out = await mapWithConcurrency([30, 10, 20, 0], 2, async (ms) => {
      await new Promise((r) => setTimeout(r, ms));
      return ms;
    });
    expect(out).toEqual([30, 10, 20, 0]);
  });

  // Each search hit costs its own mget request, so an unbounded map would open
  // one connection per hit on a full page.
  it('never exceeds the limit in flight', async () => {
    let inFlight = 0;
    let peak = 0;
    await mapWithConcurrency(
      Array.from({ length: 20 }, (_, i) => i),
      6,
      async (i) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await new Promise((r) => setTimeout(r, 1));
        inFlight--;
        return i;
      },
    );
    expect(peak).toBeLessThanOrEqual(6);
  });

  it('visits every item exactly once', async () => {
    const seen: number[] = [];
    const items = Array.from({ length: 15 }, (_, i) => i);
    await mapWithConcurrency(items, 4, async (i) => {
      seen.push(i);
      return i;
    });
    expect(seen.sort((a, b) => a - b)).toEqual(items);
  });

  it('makes no calls for an empty page', async () => {
    const worker = jest.fn();
    expect(await mapWithConcurrency([], 6, worker as any)).toEqual([]);
    expect(worker).not.toHaveBeenCalled();
  });
});
