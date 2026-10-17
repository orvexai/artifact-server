/**
 * Bounded background retry for one discovery a running process depends on.
 *
 * A transient failure (network error, timeout, 5xx, unreadable document) is
 * retried for as long as the process lives, with capped exponential backoff and
 * jitter, and a caller that needs the result can ask for an attempt now. A
 * permanent failure stops retrying, because the configuration itself is wrong
 * and only an operator can fix it.
 */

/** Spacing rules for background and on-demand discovery attempts. */
export interface DiscoveryRetryPolicy {
  /** Delay ceiling after the first failure. */
  readonly initialDelayMilliseconds: number;
  /** Largest delay ceiling between background attempts. */
  readonly maximumDelayMilliseconds: number;
  /** Shortest spacing between attempts that requests ask for. */
  readonly onDemandIntervalMilliseconds: number;
}

/** One second doubling to thirty, and at most one request-driven attempt every two seconds. */
export const defaultDiscoveryRetryPolicy: DiscoveryRetryPolicy = {
  initialDelayMilliseconds: 1_000,
  maximumDelayMilliseconds: 30_000,
  onDemandIntervalMilliseconds: 2_000,
};

/** Whether retrying can help: an outage can pass, a contradiction cannot. */
export type DiscoveryFailureKind = "misconfigured" | "transient";

export type DiscoveryState<Value> =
  | {
    readonly failures: number;
    readonly lastFailure: string | null;
    /** Epoch milliseconds of the next background attempt, when one is scheduled. */
    readonly nextAttemptAt: number | null;
    readonly status: "discovering";
  }
  | {readonly reason: string; readonly status: "misconfigured"}
  | {readonly status: "ready"; readonly value: Value};

/** Operator-facing transitions, emitted once each. */
export type DiscoveryEvent =
  | {
    readonly failures: number;
    readonly kind: "retrying";
    readonly reason: string;
    readonly retryInMilliseconds: number;
  }
  | {readonly kind: "misconfigured"; readonly reason: string}
  | {readonly failures: number; readonly kind: "recovered"};

export interface RetryingDiscoveryOptions<Value> {
  readonly attempt: () => Promise<Value>;
  readonly classify: (cause: unknown) => DiscoveryFailureKind;
  readonly describe: (cause: unknown) => string;
  readonly now?: () => number;
  readonly onEvent?: (event: DiscoveryEvent) => void;
  readonly policy?: DiscoveryRetryPolicy;
  /** Uniform random source in [0, 1); injected by tests. */
  readonly random?: () => number;
}

/**
 * Delay before the next attempt after `failures` consecutive failures.
 *
 * The ceiling doubles from the initial delay up to the maximum, and the delay
 * is drawn from the upper half of it ("equal jitter"), so replicas started
 * together spread out without ever retrying in a tight loop.
 */
export function discoveryRetryDelayMilliseconds(
  failures: number,
  policy: DiscoveryRetryPolicy,
  random: () => number,
): number {
  const exponent = Math.min(Math.max(failures, 1) - 1, 30);
  const ceiling = Math.min(
    policy.maximumDelayMilliseconds,
    policy.initialDelayMilliseconds * 2 ** exponent,
  );
  const half = ceiling / 2;
  const unit = Math.min(Math.max(random(), 0), 1);
  return Math.max(1, Math.round(half + unit * half));
}

/** One discovery that succeeds once, fails permanently once, or keeps retrying. */
export class RetryingDiscovery<Value> {
  readonly #options: RetryingDiscoveryOptions<Value>;
  readonly #now: () => number;
  readonly #policy: DiscoveryRetryPolicy;
  readonly #random: () => number;
  #closed = false;
  #inFlight: Promise<void> | null = null;
  #lastAttemptStartedAt: number | null = null;
  #state: DiscoveryState<Value> = {
    failures: 0,
    lastFailure: null,
    nextAttemptAt: null,
    status: "discovering",
  };
  #timer: ReturnType<typeof setTimeout> | null = null;

  constructor(options: RetryingDiscoveryOptions<Value>) {
    this.#options = options;
    this.#now = options.now ?? Date.now;
    this.#policy = options.policy ?? defaultDiscoveryRetryPolicy;
    this.#random = options.random ?? Math.random;
  }

  /** The latest outcome, without starting anything. */
  current(): DiscoveryState<Value> {
    return this.#state;
  }

  /** Run the first attempt; a transient failure keeps retrying in the background. */
  start(): Promise<DiscoveryState<Value>> {
    return this.#run();
  }

  /**
   * Ask for an attempt now. A running attempt is joined rather than doubled,
   * and an attempt that started within the on-demand interval is not repeated,
   * so a burst of requests during an outage reaches the issuer at most once.
   */
  async refresh(): Promise<DiscoveryState<Value>> {
    if (this.#state.status !== "discovering" || this.#closed) return this.#state;
    if (this.#inFlight !== null) return this.#run();
    const lastStarted = this.#lastAttemptStartedAt;
    if (
      lastStarted !== null &&
      this.#now() - lastStarted < this.#policy.onDemandIntervalMilliseconds
    ) {
      return this.#state;
    }
    return this.#run();
  }

  /** Stop background retries; the current state stays readable. */
  close(): void {
    this.#closed = true;
    this.#clearTimer();
  }

  #run(): Promise<DiscoveryState<Value>> {
    let inFlight = this.#inFlight;
    if (inFlight === null) {
      this.#clearTimer();
      inFlight = this.#attempt().finally(() => {
        this.#inFlight = null;
      });
      this.#inFlight = inFlight;
    }
    return inFlight.then(() => this.#state);
  }

  async #attempt(): Promise<void> {
    this.#lastAttemptStartedAt = this.#now();
    const failures = this.#state.status === "discovering"
      ? this.#state.failures
      : 0;
    let value: Value;
    try {
      value = await this.#options.attempt();
    } catch (cause) {
      this.#fail(cause, failures);
      return;
    }
    this.#state = {status: "ready", value};
    if (failures > 0) this.#emit({failures, kind: "recovered"});
  }

  #fail(cause: unknown, previousFailures: number): void {
    const reason = this.#options.describe(cause);
    if (this.#options.classify(cause) === "misconfigured") {
      this.#state = {reason, status: "misconfigured"};
      this.#emit({kind: "misconfigured", reason});
      return;
    }
    const failures = previousFailures + 1;
    const delay = discoveryRetryDelayMilliseconds(
      failures,
      this.#policy,
      this.#random,
    );
    this.#state = {
      failures,
      lastFailure: reason,
      nextAttemptAt: this.#closed ? null : this.#now() + delay,
      status: "discovering",
    };
    this.#emit({failures, kind: "retrying", reason, retryInMilliseconds: delay});
    if (this.#closed) return;
    const timer = setTimeout(() => {
      this.#timer = null;
      void this.#run();
    }, delay);
    // A pending retry must never keep a finished process alive.
    timer.unref();
    this.#timer = timer;
  }

  #clearTimer(): void {
    if (this.#timer === null) return;
    clearTimeout(this.#timer);
    this.#timer = null;
  }

  #emit(event: DiscoveryEvent): void {
    try {
      this.#options.onEvent?.(event);
    } catch {
      // Reporting must never change the discovery outcome.
    }
  }
}
