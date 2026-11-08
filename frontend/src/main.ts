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
            <p>Run a read-only evaluation and before/after simulation using sample rules for the local-demo tenant. These previews do not grant or change real permissions.</p>
            <button [disabled]="previewLoading()" (click)="runEvaluation()">Evaluate sample access</button>
            <button [disabled]="previewLoading()" (click)="runSimulation()">Simulate removal of access</button>
            @if (previewLoading()) { <p role="status">Running preview…</p> }
            @if (previewError()) { <p role="alert">{{ previewError() }}</p> }
            @if (previewResult()) {
              <h4>Backend response</h4>
              <pre aria-live="polite">{{ previewResult() }}</pre>
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
  private readonly api = new SentinelApiClient(() => this.oauth.getAccessToken() || null);

  private readonly sampleRequest = {
    tenantId: 'local-demo',
    resourceId: 'ledger',
    action: 'read',
    roles: ['analyst'],
    attributes: { department: 'finance' },
  };
  private readonly sampleRule = {
    ...this.sampleRequest,
    effect: 'ALLOW' as const,
  };

  async runEvaluation(): Promise<void> {
    await this.runPreview(() => this.api.evaluate({
      request: this.sampleRequest,
      rules: [this.sampleRule],
    }));
  }

  async runSimulation(): Promise<void> {
    await this.runPreview(() => this.api.simulate({
      subjects: [{ userId: 'sample-analyst', request: this.sampleRequest }],
      before: [this.sampleRule],
      after: [],
    }));
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
  logout(): void { this.oauth.logOut(); this.authenticated.set(false); this.previewResult.set(''); this.previewError.set(''); }
}

bootstrapApplication(AppComponent, {
  providers: [provideHttpClient(), provideOAuthClient()],
}).catch((error: unknown) => console.error('Sentinel frontend failed to start', error));
