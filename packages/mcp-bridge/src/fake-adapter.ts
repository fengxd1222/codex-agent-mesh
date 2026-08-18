export type FakeAdapterEvent =
  | { type: "lifecycle"; state: string }
  | { type: "text"; text?: string; bytes?: number }
  | { type: "terminal"; state: string }
  | { type: "approval"; operation: string }
  | { type: "cancelled" }
  | { type: "delay"; milliseconds: number }
  | { type: "raw"; line: string }
  | { type: "crash"; code: number };

export type FakeAdapterSequence = { name: string; events: FakeAdapterEvent[] };

export type FakeClock = { sleep(milliseconds: number): void | Promise<void> };

/** Deterministic test-only stream runner; no provider processes or credentials. */
export async function runFakeSequence(
  sequence: FakeAdapterSequence,
  emit: (event: FakeAdapterEvent) => void | Promise<void>,
  clock: FakeClock = { sleep: () => undefined },
): Promise<void> {
  for (const event of sequence.events) {
    if (event.type === "delay") {
      await clock.sleep(event.milliseconds);
    } else if (event.type === "crash") {
      throw new Error(`fake adapter crashed with code ${event.code}`);
    } else {
      await emit(event);
    }
  }
}
