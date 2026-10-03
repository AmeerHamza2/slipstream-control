/**
 * Minimal Prometheus text exposition, no dependency. Label sets are bounded: routes are
 * the registered route patterns (or "unmatched"), statuses are HTTP codes.
 */
export class Metrics {
  private readonly responses = new Map<string, { count: number; seconds: number }>();
  private readonly gauges: Array<() => string> = [];

  observe(route: string, status: number, seconds: number): void {
    const key = `route="${route}",status="${status}"`;
    const m = this.responses.get(key);
    if (m) {
      m.count++;
      m.seconds += seconds;
    } else {
      this.responses.set(key, { count: 1, seconds });
    }
  }

  /** Register a callback that renders extra metric lines at scrape time. */
  addCollector(fn: () => string): void {
    this.gauges.push(fn);
  }

  render(): string {
    const lines = [
      '# HELP billing_http_responses_total HTTP responses by route and status.',
      '# TYPE billing_http_responses_total counter',
    ];
    for (const [k, v] of this.responses) lines.push(`billing_http_responses_total{${k}} ${v.count}`);
    lines.push(
      '# HELP billing_http_response_seconds_sum Total time spent answering, by route and status.',
      '# TYPE billing_http_response_seconds_sum counter',
    );
    for (const [k, v] of this.responses) lines.push(`billing_http_response_seconds_sum{${k}} ${v.seconds.toFixed(6)}`);
    for (const g of this.gauges) lines.push(g());
    return lines.join('\n') + '\n';
  }
}
