import 'express-async-errors';

import { authGuard } from '@api/guards/auth.guard';
import { McpService } from '@api/integrations/mcp/mcp.service';
import { Request, Response, Router } from 'express';

type OAuthRequest = {
  client_id?: string;
  redirect_uri?: string;
  response_type?: string;
  code_challenge?: string;
  code_challenge_method?: string;
  scope?: string | string[];
  state?: string;
  resource?: string;
  instance_names?: string | string[];
  scopes?: string | string[];
  admin_api_key?: string;
};

const asString = (value: unknown) => (typeof value === 'string' ? value : undefined);

const asList = (value: unknown) => {
  if (Array.isArray(value)) return value.filter((item): item is string => typeof item === 'string');
  if (typeof value === 'string') return value.split(/[,\s]+/).filter(Boolean);
  return [];
};

const escapeHtml = (value: unknown) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const errorStatus = (error: any) => (Number.isInteger(error?.status) ? error.status : 400);
const errorMessage = (error: any) => error?.message || error?.error || 'Request failed';

export class McpRouter {
  public readonly router: Router;

  constructor(private readonly mcpService: McpService) {
    this.router = Router();

    this.router.get('/.well-known/oauth-authorization-server', this.metadata);
    this.router.get('/.well-known/oauth-protected-resource', this.protectedResourceMetadata);
    this.router.post('/register', this.registerClient);
    this.router.get('/authorize', this.authorize);
    this.router.post('/authorize', this.authorize);
    this.router.post('/token', this.token);
    this.router.post('/revoke', this.revoke);

    this.router.get('/mcp/admin/instances', authGuard.apikey, this.adminInstances);
    this.router.get('/mcp/admin/connections', authGuard.apikey, this.adminConnections);
    this.router.patch('/mcp/admin/connections/:id', authGuard.apikey, this.adminUpdateConnection);
    this.router.post('/mcp/admin/connections/:id/revoke', authGuard.apikey, this.adminRevokeConnection);

    this.router.all('/mcp', this.mcp);
  }

  private readonly hostEnabled = (req: Request, res: Response) => {
    if (!this.mcpService.isEnabled() || !this.mcpService.isPublicHost(req)) {
      res.status(404).json({ error: 'Not found' });
      return false;
    }
    return true;
  };

  private readonly enabled = (res: Response) => {
    if (!this.mcpService.isEnabled()) {
      res.status(404).json({ error: 'Not found' });
      return false;
    }
    return true;
  };

  private readonly metadata = (req: Request, res: Response) => {
    if (!this.hostEnabled(req, res)) return;
    res.json(this.mcpService.auth.metadata());
  };

  private readonly protectedResourceMetadata = (req: Request, res: Response) => {
    if (!this.hostEnabled(req, res)) return;
    res.json(this.mcpService.auth.protectedResourceMetadata());
  };

  private readonly registerClient = async (req: Request, res: Response) => {
    if (!this.hostEnabled(req, res)) return;

    try {
      const result = await this.mcpService.auth.registerClient(req.body || {});
      res.status(201).json(result);
    } catch (error) {
      res.status(errorStatus(error)).json({ error: errorMessage(error) });
    }
  };

  private readonly authorize = async (req: Request, res: Response) => {
    if (!this.hostEnabled(req, res)) return;

    const input = (req.method === 'GET' ? req.query : req.body || {}) as OAuthRequest;
    const authorizationInput = {
      clientId: asString(input.client_id) || '',
      redirectUri: asString(input.redirect_uri) || '',
      responseType: asString(input.response_type) || '',
      codeChallenge: asString(input.code_challenge) || '',
      codeChallengeMethod: asString(input.code_challenge_method) || '',
      scope: asList(input.scope),
      state: asString(input.state),
      resource: asString(input.resource),
    };
    const instanceNames = asList(input.instance_names);
    const scopes = asList(input.scopes).length > 0 ? asList(input.scopes) : authorizationInput.scope;
    if (req.method === 'GET' && !req.get('x-admin-api-key') && !req.get('apikey')) {
      try {
        await this.mcpService.auth.validateAuthorization(authorizationInput);
        res.type('html').send(`<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Authorize Evolution MCP</title></head>
  <body>
    <h1>Authorize Evolution MCP</h1>
    <p>Approve <strong>${escapeHtml(authorizationInput.clientId)}</strong> for selected Evolution instances.</p>
    <form method="post" action="/authorize">
      ${Object.entries({
        client_id: authorizationInput.clientId,
        redirect_uri: authorizationInput.redirectUri,
        response_type: authorizationInput.responseType,
        code_challenge: authorizationInput.codeChallenge,
        code_challenge_method: authorizationInput.codeChallengeMethod,
        scope: authorizationInput.scope.join(' '),
        state: authorizationInput.state,
        resource: authorizationInput.resource,
      })
        .filter(([, value]) => value)
        .map(([key, value]) => `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(value)}">`)
        .join('\n')}
      <label>Instance names (comma-separated)
        <input name="instance_names" value="${escapeHtml(instanceNames.join(','))}" required>
      </label>
      <br>
      <label>Administrator API key
        <input type="password" name="admin_api_key" required>
      </label>
      <br>
      <button type="submit">Approve</button>
    </form>
  </body>
</html>`);
      } catch (error) {
        res.status(errorStatus(error)).json({ error: errorMessage(error) });
      }
      return;
    }
    const adminApiKey =
      (req.method === 'GET' ? undefined : asString(input.admin_api_key)) ||
      req.get('x-admin-api-key') ||
      req.get('apikey') ||
      '';

    try {
      const result = await this.mcpService.auth.approveAuthorization(
        authorizationInput,
        instanceNames,
        scopes,
        adminApiKey,
      );
      const redirect = new URL(authorizationInput.redirectUri);
      redirect.searchParams.set('code', result.code);
      if (result.state) redirect.searchParams.set('state', result.state);
      res.redirect(302, redirect.toString());
    } catch (error) {
      res.status(errorStatus(error)).json({ error: errorMessage(error) });
    }
  };

  private readonly token = async (req: Request, res: Response) => {
    if (!this.hostEnabled(req, res)) return;

    const body = req.body || {};
    try {
      const clientId = asString(body.client_id) || '';
      if (body.grant_type === 'authorization_code') {
        const result = await this.mcpService.auth.exchangeAuthorizationCode(
          asString(body.code) || '',
          clientId,
          asString(body.redirect_uri) || '',
          asString(body.code_verifier) || '',
          asString(body.client_secret),
        );
        res.json(result);
        return;
      }

      if (body.grant_type === 'refresh_token') {
        res.json(
          await this.mcpService.auth.refresh(
            asString(body.refresh_token) || '',
            clientId,
            asString(body.client_secret),
          ),
        );
        return;
      }

      res.status(400).json({ error: 'unsupported_grant_type' });
    } catch (error) {
      res.status(errorStatus(error)).json({ error: errorMessage(error) });
    }
  };

  private readonly revoke = async (req: Request, res: Response) => {
    if (!this.hostEnabled(req, res)) return;

    try {
      const token = asString(req.body?.token) || '';
      if (!token) {
        res.status(400).json({ error: 'token is required' });
        return;
      }
      await this.mcpService.auth.revoke(token);
      res.status(200).json({ revoked: true });
    } catch (error) {
      res.status(errorStatus(error)).json({ error: errorMessage(error) });
    }
  };

  private readonly adminInstances = async (req: Request, res: Response) => {
    if (!this.enabled(res)) return;
    res.json(await this.mcpService.auth.adminInstances());
  };

  private readonly adminConnections = async (req: Request, res: Response) => {
    if (!this.enabled(res)) return;
    const connections = await this.mcpService.auth.adminConnections();
    res.json(
      connections.map(({ client, ...connection }) => ({
        ...connection,
        client: {
          id: client.id,
          clientId: client.clientId,
          clientName: client.clientName,
          redirectUris: client.redirectUris,
          createdAt: client.createdAt,
          updatedAt: client.updatedAt,
        },
      })),
    );
  };

  private readonly adminUpdateConnection = async (req: Request, res: Response) => {
    if (!this.enabled(res)) return;

    try {
      const body = req.body || {};
      res.json(
        await this.mcpService.auth.adminUpdateConnection(req.params.id, {
          scopes: Array.isArray(body.scopes) ? body.scopes : undefined,
          instanceNames: Array.isArray(body.instanceNames) ? body.instanceNames : undefined,
          status: asString(body.status),
        }),
      );
    } catch (error) {
      res.status(errorStatus(error)).json({ error: errorMessage(error) });
    }
  };

  private readonly adminRevokeConnection = async (req: Request, res: Response) => {
    if (!this.enabled(res)) return;

    try {
      res.json(await this.mcpService.auth.adminRevokeConnection(req.params.id));
    } catch (error) {
      res.status(errorStatus(error)).json({ error: errorMessage(error) });
    }
  };

  private readonly mcp = async (req: Request, res: Response) => {
    await this.mcpService.handleMcp(req, res);
  };
}
