import { SentinelApiClient } from './sentinel-api';
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
    this.previewLoading.set(true);
    this.previewError.set('');
    this.previewResult.set('');
    try {
      const response = await operation();
      this.previewResult.set(JSON.stringify(response, null, 2) ?? 'Empty response');
    } catch (error) {
      this.previewError.set(error instanceof Error ? error.message : 'Preview failed');
    } finally {
      this.previewLoading.set(false);
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
    if (this.riskLoading()) return;
    this.riskLoading.set(true);
    this.riskError.set('');
    this.riskResult.set('');
    try {
      const response = await operation();
      this.riskResult.set(JSON.stringify(response, null, 2) ?? 'Empty response');
    } catch (error) {
      this.riskError.set(error instanceof Error ? error.message : 'Risk preview failed');
    } finally {
      this.riskLoading.set(false);
    }
  }

  ngOnInit(): void { void this.initialize(); }

  async initialize(): Promise<void> {
    this.loading.set(true);
    this.error.set('');
    try {
      this.oauth.configure(authConfig);
      this.oauth.setupAutomaticSilentRefresh();
      await this.oauth.loadDiscoveryDocumentAndTryLogin();
      this.authenticated.set(this.oauth.hasValidAccessToken());
      if (this.authenticated()) {
        const claims = this.oauth.getIdentityClaims() as Record<string, unknown> | null;
        this.displayName.set(String(claims?.['preferred_username'] ?? claims?.['sub'] ?? 'user'));
        // The tenant claim is in the ACCESS token, not the ID token.
        // Do not decode it here or trust client-side claims for authorization.
        this.tenantId.set('Resolved by the backend from your access token');
      }
    } catch {
      this.error.set('Cannot reach Keycloak. Start the local Compose stack and confirm the realm is imported.');
    } finally {
      this.loading.set(false);
    }
  }

  login(): void { this.oauth.initCodeFlow(); }
  logout(): void { this.oauth.logOut(); this.authenticated.set(false); this.previewResult.set(''); this.previewError.set(''); this.riskResult.set(''); this.riskError.set(''); } 
}

bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(), provideOAuthClient()],
}).catch((error: unknown) => console.error('Sentinel frontend failed to start', error));
