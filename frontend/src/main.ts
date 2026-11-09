import { SentinelApiClient, type ApprovalRequest } from './sentinel-api';
import { Component, inject, OnInit, signal } from '@angular/core';
import { bootstrapApplication } from '@angular/platform-browser';
import { provideHttpClient } from '@angular/common/http';
import { OAuthService, provideOAuthClient, AuthConfig } from 'angular-oauth2-oidc';

const authConfig: AuthConfig = {
  issuer: 'http://localhost:8081/realms/sentinel',
  redirectUri: window.location.origin + '/',
  clientId: 'sentinel-angular',
  responseType: 'code',
  scope: 'openid profile email',
  requireHttps: false, // Loopback development only; never use with a remote issuer.
  strictDiscoveryDocumentValidation: true,
  showDebugInformation: false,
  clearHashAfterLogin: true,
};

@Component({
  selector: 'app-root',
  standalone: true,
  template: `
    <main>
      <div class="eyebrow">Sentinel / Identity Intelligence</div>
      <h1>Understand access.<br>Prevent privilege risk.</h1>
      <p>Review permissions, simulate policy changes, and keep a verifiable history of decisions.</p>
      <section class="card" aria-live="polite">
        @if (loading()) {
          <p>Connecting to your identity provider…</p>
        } @else if (error()) {
          <h2>Authentication unavailable</h2>
          <p>{{ error() }}</p>
          <button (click)="initialize()">Retry connection</button>
        } @else if (authenticated()) {
          <span class="badge">Authenticated</span>
          <h2>Welcome to Sentinel</h2>
          <p>Signed in as <code>{{ displayName() }}</code>.</p>
          <p>Tenant: <code>{{ tenantId() }}</code></p>
          <section aria-labelledby="preview-heading">
            <h3 id="preview-heading">Access policy preview</h3>
            <p>Explore read-only policy decisions for the local-demo tenant. Change the resource, action, and role, then compare access before and after removing an allow rule. No real permissions are modified.</p>
            <div class="preview-inputs">
              <label>Resource <input aria-label="Resource" [value]="resourceId()" (input)="resourceId.set($any($event.target).value)" maxlength="80" /></label>
              <label>Action <select aria-label="Action" [value]="action()" (change)="action.set($any($event.target).value)"><option value="read">read</option><option value="write">write</option><option value="approve">approve</option></select></label>
              <label>Role <input aria-label="Role" [value]="role()" (input)="role.set($any($event.target).value)" maxlength="80" /></label>
            </div>
            <button [disabled]="previewLoading()" (click)="runEvaluation()">Evaluate sample access</button>
            <button [disabled]="previewLoading()" (click)="runSimulation()">Simulate removal of access</button>
            @if (previewLoading()) { <p role="status">Running preview…</p> }
            @if (previewError()) { <p role="alert">{{ previewError() }}</p> }
            @if (previewResult()) {
              <h4>Backend response</h4>
              <pre aria-live="polite">{{ previewResult() }}</pre>
            }
          </section>
          <section aria-labelledby="risk-heading">
            <h3 id="risk-heading">Access risk explorer</h3>
            <p>Analyze illustrative grants or compare risk before and after removing an excessive privilege. These are sample inputs, not findings from your organization's directory.</p>
            <button [disabled]="riskLoading()" (click)="runRiskAnalysis()">Analyze sample grants</button>
            <button [disabled]="riskLoading()" (click)="runRiskComparison()">Compare proposed remediation</button>
            @if (riskLoading()) { <p role="status">Analyzing sample grants…</p> }
            @if (riskError()) { <p role="alert">{{ riskError() }}</p> }
            @if (riskResult()) {
              <h4>Risk analysis response</h4>
              <pre aria-live="polite">{{ riskResult() }}</pre>
            }
          </section>
          <section aria-labelledby="approvals-heading">
            <h3 id="approvals-heading">Pending access approvals</h3>
            <p>Review tenant-scoped requests. Decisions are audited by the backend and cannot be undone.</p>
            <button [disabled]="approvalsLoading() || decisionId() !== ''" (click)="loadApprovals()">Refresh approvals</button>
            @if (approvalsLoading()) { <p role="status">Loading approvals…</p> }
            @if (approvalsError()) { <p role="alert">{{ approvalsError() }}</p> }
            @if (approvalsNotice()) { <p role="status">{{ approvalsNotice() }}</p> }
            @if (!approvalsLoading() && approvals().length === 0 && !approvalsError()) {
              <p>No approvals loaded. Refresh to check the queue.</p>
            }
            @for (approval of approvals(); track approval.id) {
              <article class="approval-item">
                <h4>{{ approval.resourceId }}</h4>
                <p>Requested by {{ approval.requesterId }} · Version {{ approval.version }}</p>
                <p>{{ approval.justification }}</p>
                <button [disabled]="decisionId() !== ''" (click)="decide(approval, 'APPROVE')">Approve</button>
                <button [disabled]="decisionId() !== ''" (click)="decide(approval, 'REJECT')">Reject</button>
              </article>
            }
          </section>
          <button (click)="logout()">Sign out</button>
        } @else {
          <h2>Secure workspace</h2>
          <p>Sign in with your local Keycloak identity to continue. No demo credentials are embedded in the app.</p>
          <button (click)="login()">Sign in with Keycloak</button>
        }
      </section>
    </main>
  `,
})
class AppComponent implements OnInit {
  private readonly oauth = inject(OAuthService);
  readonly loading = signal(true);
  readonly error = signal('');
  readonly authenticated = signal(false);
  readonly displayName = signal('');
  readonly tenantId = signal('');
  readonly previewLoading = signal(false);
  readonly previewError = signal('');
  readonly previewResult = signal('');
  readonly riskLoading = signal(false);
  readonly riskError = signal('');
  readonly riskResult = signal('');
  readonly approvals = signal<ApprovalRequest[]>([]);
  readonly approvalsLoading = signal(false);
  readonly approvalsError = signal('');
  readonly approvalsNotice = signal('');
  readonly decisionId = signal('');
  // Invalidate outstanding preview responses when the session changes.
  private sessionEpoch = 0;
  private readonly api = new SentinelApiClient(() => this.oauth.getAccessToken() || null);

  readonly resourceId = signal('ledger');
  readonly action = signal('read');
  readonly role = signal('analyst');

  private previewInputs() {
    const resourceId = this.resourceId().trim();
    const role = this.role().trim();
    if (!resourceId || !role) {
      throw new Error('Resource and role are required for a policy preview');
    }
    if (!/^[a-zA-Z0-9_.:-]{1,80}$/.test(resourceId) || !/^[a-zA-Z0-9_.:-]{1,80}$/.test(role)) {
      throw new Error('Resource and role may contain letters, numbers, dots, underscores, colons and hyphens');
    }
    const request = {
      tenantId: 'local-demo',
      resourceId,
      action: this.action(),
      roles: [role],
      attributes: { department: 'finance' },
    };
    return { request, rule: { ...request, effect: 'ALLOW' as const } };
  }

  async runEvaluation(): Promise<void> {
    await this.runPreview(() => {
      const { request, rule } = this.previewInputs();
      return this.api.evaluate({ request, rules: [rule] });
    });
  }

  async runSimulation(): Promise<void> {
    await this.runPreview(() => {
      const { request, rule } = this.previewInputs();
      return this.api.simulate({
        subjects: [{ userId: 'sample-analyst', request }],
        before: [rule],
        after: [],
      });
    });
  }

  private async runPreview(operation: () => Promise<unknown>): Promise<void> {
    if (!this.authenticated() || this.previewLoading()) return;
    const epoch = this.sessionEpoch;
    this.previewLoading.set(true);
    this.previewError.set('');
    this.previewResult.set('');
    try {
      const response = await operation();
      if (epoch === this.sessionEpoch) this.previewResult.set(JSON.stringify(response, null, 2) ?? 'Empty response');
    } catch (error) {
      if (epoch === this.sessionEpoch) this.previewError.set(error instanceof Error ? error.message : 'Preview failed');
    } finally {
      if (epoch === this.sessionEpoch) this.previewLoading.set(false);
    }
  }

  private sampleGrants() {
    return [
      { tenantId: 'local-demo', userId: 'sample-analyst', resourceId: 'ledger', permission: '*', activeUser: true },
      { tenantId: 'local-demo', userId: 'former-employee', resourceId: 'ledger', permission: 'read', activeUser: false },
      { tenantId: 'local-demo', userId: 'sample-analyst', resourceId: 'payments', permission: 'payment:approve', activeUser: true },
      { tenantId: 'local-demo', userId: 'sample-analyst', resourceId: 'payments', permission: 'payment:execute', activeUser: true },
    ];
  }

  async runRiskAnalysis(): Promise<void> {
    await this.runRisk(() => this.api.analyzeRisks({ grants: this.sampleGrants() }));
  }

  async runRiskComparison(): Promise<void> {
    const before = this.sampleGrants();
    const after = before.filter(grant => grant.permission !== '*');
    await this.runRisk(() => this.api.compareRisks({ before, after }));
  }

  private async runRisk(operation: () => Promise<unknown>): Promise<void> {
    if (!this.authenticated() || this.riskLoading()) return;
    const epoch = this.sessionEpoch;
    this.riskLoading.set(true);
    this.riskError.set('');
    this.riskResult.set('');
    try {
      const response = await operation();
      if (epoch === this.sessionEpoch) this.riskResult.set(JSON.stringify(response, null, 2) ?? 'Empty response');
    } catch (error) {
      if (epoch === this.sessionEpoch) this.riskError.set(error instanceof Error ? error.message : 'Risk preview failed');
    } finally {
      if (epoch === this.sessionEpoch) this.riskLoading.set(false);
    }
  }

  async loadApprovals(): Promise<void> {
    if (!this.authenticated() || this.approvalsLoading() || this.decisionId()) return;
    const epoch = this.sessionEpoch;
    this.approvalsLoading.set(true);
    this.approvalsError.set('');
    this.approvalsNotice.set('');
    try {
      const queue = await this.api.pendingApprovals();
      if (epoch === this.sessionEpoch) this.approvals.set(queue);
    } catch (error) {
      if (epoch === this.sessionEpoch) this.approvalsError.set(
        error instanceof Error ? error.message : 'Unable to load approvals');
    } finally {
      if (epoch === this.sessionEpoch) this.approvalsLoading.set(false);
    }
  }

  async decide(approval: ApprovalRequest, action: 'APPROVE' | 'REJECT'): Promise<void> {
    if (!this.authenticated() || this.decisionId() || approval.status !== 'PENDING') return;
    if (!window.confirm(`${action === 'APPROVE' ? 'Approve' : 'Reject'} access request ${approval.id}?`)) return;
    const epoch = this.sessionEpoch;
    this.decisionId.set(approval.id);
    this.approvalsError.set('');
    this.approvalsNotice.set('');
    try {
      await this.api.decideApproval(approval.id, action, approval.version);
      if (epoch === this.sessionEpoch) {
        this.approvals.set(this.approvals().filter(item => item.id !== approval.id));
        this.approvalsNotice.set(`Request ${approval.id} ${action === 'APPROVE' ? 'approved' : 'rejected'}.`);
      }
    } catch (error) {
      if (epoch === this.sessionEpoch) {
        this.approvalsError.set(error instanceof Error ? error.message : 'Decision failed');
        // On conflict, require an explicit refresh rather than retrying a stale version.
      }
    } finally {
      if (epoch === this.sessionEpoch) this.decisionId.set('');
    }
  }

  ngOnInit(): void { void this.initialize(); }

  async initialize(): Promise<void> {
    // Reinitialization must not allow responses from a previous session to render.
    const epoch = ++this.sessionEpoch;
    this.api.cancelPendingRequests();
    this.authenticated.set(false);
    this.previewLoading.set(false);
    this.riskLoading.set(false);
    this.approvals.set([]);
    this.approvalsLoading.set(false);
    this.approvalsError.set('');
    this.approvalsNotice.set('');
    this.decisionId.set('');
    this.previewResult.set('');
    this.riskResult.set('');
    this.previewError.set('');
    this.riskError.set('');
    this.loading.set(true);
    this.error.set('');
    try {
      this.oauth.configure(authConfig);
      this.oauth.setupAutomaticSilentRefresh();
      await this.oauth.loadDiscoveryDocumentAndTryLogin();
      if (epoch !== this.sessionEpoch) return;
      this.authenticated.set(this.oauth.hasValidAccessToken());
      if (this.authenticated()) {
        const claims = this.oauth.getIdentityClaims() as Record<string, unknown> | null;
        this.displayName.set(String(claims?.['preferred_username'] ?? claims?.['sub'] ?? 'user'));
        // The tenant claim is in the ACCESS token, not the ID token.
        // Do not decode it here or trust client-side claims for authorization.
        this.tenantId.set('Resolved by the backend from your access token');
      }
    } catch {
      if (epoch !== this.sessionEpoch) return;
      this.error.set('Cannot reach Keycloak. Start the local Compose stack and confirm the realm is imported.');
    } finally {
      if (epoch === this.sessionEpoch) this.loading.set(false);
    }
  }

  login(): void { this.oauth.initCodeFlow(); }
  logout(): void {
    this.sessionEpoch++;
    this.api.cancelPendingRequests();
    this.loading.set(false);
    this.error.set('');
    this.displayName.set('');
    this.tenantId.set('');
    this.authenticated.set(false);
    this.previewLoading.set(false);
    this.riskLoading.set(false);
    this.approvals.set([]);
    this.approvalsLoading.set(false);
    this.approvalsError.set('');
    this.approvalsNotice.set('');
    this.decisionId.set('');
    this.previewResult.set('');
    this.previewError.set('');
    this.riskResult.set('');
    this.riskError.set('');
    this.oauth.logOut();
  } 
}

bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(), provideOAuthClient()],
}).catch((error: unknown) => console.error('Sentinel frontend failed to start', error));
