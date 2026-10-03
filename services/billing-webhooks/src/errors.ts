export type ErrorCode =
  | 'invalid_request'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'payment_required'
  | 'internal';

/** An error that maps directly to the contract's `{"error": {...}}` response. */
export class HttpError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: ErrorCode,
    message: string,
    /** Sent as `Retry-After` (seconds) on 429/503. */
    readonly retryAfterS?: number,
  ) {
    super(message);
  }
}

export const badRequest = (msg: string) => new HttpError(400, 'invalid_request', msg);
export const unauthorized = (msg = 'authentication required') => new HttpError(401, 'unauthorized', msg);
/** Upstream (api / Google) failure: retryable by the caller. Contract code stays `internal`. */
export const upstream = (status: 502 | 503, msg: string, retryAfterS?: number) =>
  new HttpError(status, 'internal', msg, retryAfterS);
export const forbidden = (msg: string) => new HttpError(403, 'forbidden', msg);
