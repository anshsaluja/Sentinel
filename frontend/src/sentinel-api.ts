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

export interface ApprovalRequest {
  id: string;
  tenantId: string;
  requesterId: string;
  approverId: string | null;
  resourceId: string;
  justification: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED';
  version: number;
  updatedAt: string;
}

export type AccessTokenProvider = () => string | null;

/**
 * The endpoints return server-owned shapes. Keep them unknown until their
 * response contracts are verified against the backend; never invent fields.
 */
export class SentinelApiClient {
  private readonly pendingRequests = new Set<AbortController>();

  /** Cancel outstanding previews when the authenticated session ends. */
  cancelPendingRequests(): void {
    for (const controller of this.pendingRequests) controller.abort();
    this.pendingRequests.clear();
  }

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

  async pendingApprovals(): Promise<ApprovalRequest[]> {
    const payload = await this.request('/api/v1/approvals/pending', 'GET');
    if (!Array.isArray(payload) || !payload.every(isApprovalRequest)) {
      throw new SentinelApiError('Invalid approval queue response', null);
    }
    return payload;
  }

  async decideApproval(id: string, action: 'APPROVE' | 'REJECT', expectedVersion: number): Promise<ApprovalRequest> {
    if (!/^[a-zA-Z0-9_.:-]{1,120}$/.test(id) ||
        !Number.isSafeInteger(expectedVersion) || expectedVersion < 0) {
      throw new SentinelApiError('Invalid approval request', null);
    }
    const payload = await this.request(
      `/api/v1/approvals/${encodeURIComponent(id)}/decision`,
      'POST', { action, expectedVersion },
    );
    if (!isApprovalRequest(payload)) {
      throw new SentinelApiError('Invalid approval decision response', null);
    }
    return payload;
  }

  private post(path: string, body: unknown): Promise<unknown> {
    return this.request(path, 'POST', body);
  }

  private async request(path: string, method: 'GET' | 'POST', body?: unknown): Promise<unknown> {
    const token = this.accessToken();
    if (!token) {
      throw new SentinelApiError('Sign in before requesting policy previews', 401);
    }
    const controller = new AbortController();
    this.pendingRequests.add(controller);
    const timer = setTimeout(() => controller.abort(), 10000);
    try {
      const response = await this.fetcher(new URL(path, this.baseUrl), {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
          Accept: 'application/json',
        },
        ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
        signal: controller.signal,
        cache: 'no-store',
      });
      if (!response.ok) {
        // Do not surface raw backend error bodies: they can contain sensitive details.
        throw new SentinelApiError(`Sentinel API returned HTTP ${response.status}`, response.status);
      }
      // Parsing can outlive fetch: a logout during response.json() must not return stale data.
      const payload: unknown = await response.json();
      if (controller.signal.aborted) {
        throw new SentinelApiError('Sentinel API request was cancelled or timed out', null);
      }
      // A token can rotate or be cleared without a component logout callback.
      // Never return a response fetched under a different authentication session.
      if (this.accessToken() !== token) {
        throw new SentinelApiError('Sentinel authentication changed during the request', 401);
      }
      return payload;
    } catch (error) {
      if (error instanceof SentinelApiError) throw error;
      if (controller.signal.aborted) {
        throw new SentinelApiError('Sentinel API request was cancelled or timed out', null);
      }
      throw new SentinelApiError('Unable to reach the local Sentinel API', null);
    } finally {
      clearTimeout(timer);
      this.pendingRequests.delete(controller);
    }
  }
}

function isApprovalRequest(value: unknown): value is ApprovalRequest {
  if (typeof value !== 'object' || value === null) return false;
  const item = value as Record<string, unknown>;
  return typeof item['id'] === 'string' &&
    /^[a-zA-Z0-9_.:-]{1,120}$/.test(item['id']) &&
    typeof item['tenantId'] === 'string' &&
    typeof item['requesterId'] === 'string' &&
    typeof item['resourceId'] === 'string' &&
    typeof item['justification'] === 'string' &&
    (item['approverId'] === null || typeof item['approverId'] === 'string') &&
    ['PENDING', 'APPROVED', 'REJECTED', 'CANCELLED'].includes(String(item['status'])) &&
    typeof item['version'] === 'number' && Number.isSafeInteger(item['version']) && item['version'] >= 0 &&
    typeof item['updatedAt'] === 'string';
}
