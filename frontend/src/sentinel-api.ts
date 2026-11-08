/**
 * Authenticated preview API transport for Sentinel's local Angular workspace.
 *
 * The backend validates JWTs and derives tenant identity from the access token.
 * This client does not interpret JWT claims or make authorization decisions.
 */
export class SentinelApiError extends Error {
  constructor(
    message: string,
    readonly status: number | null,
  ) {
    super(message);
    this.name = 'SentinelApiError';
  }
}

export interface AccessRequest {
  tenantId: string;
  resourceId: string;
  action: string;
  roles: string[];
  attributes: Record<string, string>;
}

export interface PolicyRule {
  tenantId: string;
  resourceId: string;
  action: string;
  roles: string[];
  attributes: Record<string, string>;
  effect: 'ALLOW' | 'DENY';
}

export interface EvaluationPreview {
  request: AccessRequest;
  rules: PolicyRule[];
}

export interface SimulationSubject {
  userId: string;
  request: AccessRequest;
}

export interface SimulationPreview {
  subjects: SimulationSubject[];
  before: PolicyRule[];
  after: PolicyRule[];
}

export type AccessTokenProvider = () => string | null;

/**
 * The endpoints return server-owned shapes. Keep them unknown until their
 * response contracts are verified against the backend; never invent fields.
 */
export class SentinelApiClient {
  constructor(
    private readonly accessToken: AccessTokenProvider,
    private readonly baseUrl = 'http://localhost:8080',
    private readonly fetcher: typeof fetch = fetch,
  ) {
    const url = new URL(baseUrl);
    if (url.protocol !== 'http:' || !['localhost', '127.0.0.1'].includes(url.hostname)) {
      throw new Error('Sentinel preview API must use a loopback origin');
    }
    if (url.username || url.password || url.search || url.hash) {
      throw new Error('Sentinel preview API URL must not contain credentials or query parameters');
    }
  }

  evaluate(request: EvaluationPreview): Promise<unknown> {
    return this.post('/api/v1/policies/evaluate', request);
  }

  simulate(request: SimulationPreview): Promise<unknown> {
    return this.post('/api/v1/policies/simulate', request);
  }

  analyzeRisks(request: unknown): Promise<unknown> {
    return this.post('/api/v1/risks/analyze', request);
  }

  compareRisks(request: unknown): Promise<unknown> {
    return this.post('/api/v1/risks/compare', request);
  }

  private async post(path: string, body: unknown): Promise<unknown> {
    const token = this.accessToken();
    if (!token) {
      throw new SentinelApiError('Sign in before requesting policy previews', 401);
    }
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await this.fetcher(new URL(path, this.baseUrl), {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
        cache: 'no-store',
      });
      if (!response.ok) {
        // Do not surface raw backend error bodies: they can contain sensitive details.
        throw new SentinelApiError(`Sentinel API returned HTTP ${response.status}`, response.status);
      }
      return response.json() as Promise<unknown>;
    } catch (error) {
      if (error instanceof SentinelApiError) throw error;
      if (controller.signal.aborted) {
        throw new SentinelApiError('Sentinel API request timed out', null);
      }
      throw new SentinelApiError('Unable to reach the local Sentinel API', null);
    } finally {
      clearTimeout(timer);
    }
  }
}
