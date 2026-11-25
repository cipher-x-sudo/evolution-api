import { PrismaRepository } from '@api/repository/repository.service';
import { Auth, configService, Mcp } from '@config/env.config';
import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { Prisma } from '@prisma/client';
import { createHash, randomBytes, timingSafeEqual } from 'crypto';

export const MCP_SCOPES = ['evolution:read', 'evolution:message', 'evolution:group', 'evolution:profile'];

type OAuthClientMetadata = {
  client_name?: string;
  redirect_uris?: string[];
  token_endpoint_auth_method?: string;
};

type AuthorizationInput = {
  clientId: string;
  redirectUri: string;
  responseType: string;
  codeChallenge: string;
  codeChallengeMethod: string;
  scope: string[];
  state?: string;
  resource?: string;
};

const hash = (value: string) => createHash('sha256').update(value).digest('hex');
const token = () => randomBytes(32).toString('base64url');
const json = (value: unknown) => (value ?? []) as Prisma.InputJsonValue;
const badRequest = (...message: string[]): never => {
  throw { status: 400, error: 'Bad Request', message };
};
const unauthorized = (...message: string[]): never => {
  throw { status: 401, error: 'Unauthorized', message };
};
const parseJson = <T>(value: string | unknown, fallback: T): T => {
  try {
    return (typeof value === 'string' ? JSON.parse(value) : value) as T;
  } catch {
    return fallback;
  }
};

export class McpAuthService {
  private readonly config = configService.get<Mcp>('MCP');

  constructor(private readonly prisma: PrismaRepository) {}

  public metadata() {
    const issuer = this.publicUrl();
    return {
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      registration_endpoint: `${issuer}/register`,
      revocation_endpoint: `${issuer}/revoke`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
      scopes_supported: MCP_SCOPES,
    };
  }

  public protectedResourceMetadata() {
    const resource = this.publicUrl();
    return {
      resource,
      authorization_servers: [resource],
      scopes_supported: MCP_SCOPES,
      bearer_methods_supported: ['header'],
    };
  }

  public publicUrl() {
    return (this.config.PUBLIC_URL || configService.get('SERVER').URL || '').replace(/\/+$/, '');
  }

  public async registerClient(metadata: OAuthClientMetadata) {
    const redirectUris = Array.isArray(metadata.redirect_uris) ? metadata.redirect_uris : [];

    if (!metadata.client_name || redirectUris.length === 0) {
      badRequest('client_name and redirect_uris are required');
    }
    if (redirectUris.some((uri) => typeof uri !== 'string' || uri.length > 2048)) {
      badRequest('redirect_uris must be strings no longer than 2048 characters');
    }
    const authMethod = metadata.token_endpoint_auth_method || 'none';
    if (!['none', 'client_secret_post'].includes(authMethod)) {
      badRequest('Unsupported token endpoint authentication method');
    }

    for (const uri of redirectUris) {
      let parsed: URL;
      try {
        parsed = new URL(uri);
      } catch {
        badRequest('redirect_uris must contain valid URLs');
      }
      if (
        parsed.protocol !== 'https:' &&
        !(parsed.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname))
      ) {
        badRequest('redirect_uris must use https, or http for localhost callbacks');
      }
    }

    const clientId = `evo_${token()}`;
    const clientSecret = authMethod === 'client_secret_post' ? token() : undefined;
    const client = await this.prisma.mcpClient.create({
      data: {
        clientId,
        clientSecretHash: clientSecret ? hash(clientSecret) : null,
        clientName: metadata.client_name.slice(0, 255),
        redirectUris: json(redirectUris),
      },
    });

    return {
      client_id: client.clientId,
      client_id_issued_at: Math.floor(client.createdAt.getTime() / 1000),
      ...(clientSecret ? { client_secret: clientSecret } : {}),
      client_name: client.clientName,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: authMethod,
    };
  }

  public async getClient(clientId: string) {
    const client = await this.prisma.mcpClient.findUnique({ where: { clientId } });
    if (!client) unauthorized('Unknown MCP client');
    return client;
  }

  public async validateAuthorization(input: AuthorizationInput) {
    if (input.responseType !== 'code') badRequest('response_type must be code');
    if (input.codeChallengeMethod !== 'S256' || !input.codeChallenge) {
      badRequest('PKCE S256 is required');
    }
    if (input.resource && input.resource.replace(/\/+$/, '') !== this.publicUrl()) {
      badRequest('resource does not match the MCP server');
    }

    const client = await this.getClient(input.clientId);
    const redirectUris = parseJson<string[]>(client.redirectUris, []);
    if (!redirectUris.includes(input.redirectUri)) {
      badRequest('redirect_uri is not registered');
    }

    const scopes = input.scope.filter((scope) => MCP_SCOPES.includes(scope));
    if (!scopes.includes('evolution:read')) scopes.unshift('evolution:read');

    return { client, scopes };
  }

  public async approveAuthorization(
    input: AuthorizationInput,
    instanceNames: string[],
    scopes: string[],
    apiKey: string,
  ) {
    const globalKey = configService.get<Auth>('AUTHENTICATION').API_KEY.KEY;
    const suppliedKey = Buffer.from(apiKey || '');
    const expectedKey = Buffer.from(globalKey || '');
    if (!apiKey || suppliedKey.length !== expectedKey.length || !timingSafeEqual(suppliedKey, expectedKey)) {
      unauthorized('Administrator approval is required');
    }

    const { client, scopes: requestedScopes } = await this.validateAuthorization(input);
    const finalScopes = (scopes.length ? scopes : requestedScopes).filter((scope) => requestedScopes.includes(scope));
    if (!finalScopes.includes('evolution:read')) finalScopes.unshift('evolution:read');
    const instances = await this.prisma.instance.findMany({
      where: { name: { in: instanceNames.filter(Boolean) } },
      select: { id: true, name: true },
    });

    if (instances.length === 0) badRequest('At least one valid instance must be selected');

    const connection = await this.prisma.mcpConnection.create({
      data: {
        clientId: client.id,
        status: 'approved',
        scopes: json(finalScopes),
        approvedAt: new Date(),
        instances: {
          create: instances.map((instance) => ({ instanceId: instance.id })),
        },
      },
    });

    const authorizationCode = token();
    await this.prisma.mcpAuthorizationCode.create({
      data: {
        codeHash: hash(authorizationCode),
        connectionId: connection.id,
        redirectUri: input.redirectUri,
        codeChallenge: input.codeChallenge,
        scopes: json(finalScopes),
        expiresAt: new Date(Date.now() + this.config.AUTH_CODE_TTL * 1000),
      },
    });

    return { code: authorizationCode, state: input.state };
  }

  public async exchangeAuthorizationCode(
    code: string,
    clientId: string,
    redirectUri: string,
    codeVerifier: string,
    clientSecret?: string,
  ) {
    const client = await this.getClient(clientId);
    if (client.clientSecretHash && (!clientSecret || hash(clientSecret) !== client.clientSecretHash)) {
      unauthorized('Invalid client credentials');
    }

    const record = await this.prisma.mcpAuthorizationCode.findUnique({
      where: { codeHash: hash(code) },
      include: { connection: true },
    });
    if (
      !record ||
      record.usedAt ||
      record.expiresAt.getTime() < Date.now() ||
      record.redirectUri !== redirectUri ||
      record.connection.clientId !== client.id
    ) {
      unauthorized('Invalid authorization code');
    }

    const expected = createHash('sha256').update(codeVerifier).digest('base64url');
    if (expected !== record.codeChallenge) unauthorized('Invalid PKCE verifier');

    const consumed = await this.prisma.mcpAuthorizationCode.updateMany({
      where: { id: record.id, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (consumed.count !== 1) unauthorized('Invalid authorization code');

    return this.issueTokens(record.connectionId);
  }

  public async refresh(refreshToken: string, clientId: string, clientSecret?: string) {
    const client = await this.getClient(clientId);
    this.assertClientSecret(client.clientSecretHash, clientSecret);
    const record = await this.prisma.mcpRefreshToken.findUnique({
      where: { tokenHash: hash(refreshToken) },
      include: { connection: true },
    });

    if (
      !record ||
      record.revokedAt ||
      record.rotatedAt ||
      record.expiresAt.getTime() < Date.now() ||
      record.connection.clientId !== client.id ||
      record.connection.status !== 'approved'
    ) {
      unauthorized('Invalid refresh token');
    }

    const rotated = await this.prisma.mcpRefreshToken.updateMany({
      where: { id: record.id, rotatedAt: null, revokedAt: null },
      data: { rotatedAt: new Date(), revokedAt: new Date() },
    });
    if (rotated.count !== 1) unauthorized('Invalid refresh token');

    return this.issueTokens(record.connectionId);
  }

  private assertClientSecret(expectedHash: string | null, suppliedSecret?: string) {
    if (expectedHash && (!suppliedSecret || hash(suppliedSecret) !== expectedHash)) {
      unauthorized('Invalid client credentials');
    }
  }

  private async issueTokens(connectionId: string) {
    const accessToken = token();
    const refreshToken = token();
    const accessExpiresAt = new Date(Date.now() + this.config.ACCESS_TOKEN_TTL * 1000);
    const refreshExpiresAt = new Date(Date.now() + this.config.REFRESH_TOKEN_TTL * 1000);

    await this.prisma.mcpAccessToken.create({
      data: { tokenHash: hash(accessToken), connectionId, expiresAt: accessExpiresAt },
    });
    await this.prisma.mcpRefreshToken.create({
      data: { tokenHash: hash(refreshToken), connectionId, expiresAt: refreshExpiresAt },
    });

    const connection = await this.prisma.mcpConnection.findUnique({ where: { id: connectionId } });
    return {
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: this.config.ACCESS_TOKEN_TTL,
      scope: parseJson<string[]>(connection?.scopes, []).join(' '),
    };
  }

  public async verifyAccessToken(accessToken: string): Promise<AuthInfo> {
    const record = await this.prisma.mcpAccessToken.findUnique({
      where: { tokenHash: hash(accessToken) },
      include: { connection: { include: { instances: true } } },
    });

    if (
      !record ||
      record.revokedAt ||
      record.expiresAt.getTime() < Date.now() ||
      record.connection.status !== 'approved' ||
      record.connection.revokedAt
    ) {
      unauthorized('Invalid access token');
    }

    await this.prisma.mcpConnection.update({
      where: { id: record.connectionId },
      data: { lastUsedAt: new Date() },
    });

    return {
      token: accessToken,
      clientId: record.connection.clientId,
      scopes: parseJson<string[]>(record.connection.scopes, []),
      expiresAt: Math.floor(record.expiresAt.getTime() / 1000),
      resource: new URL(this.publicUrl()),
      extra: {
        connectionId: record.connectionId,
        instanceIds: record.connection.instances.map((instance) => instance.instanceId),
      },
    };
  }

  public async revoke(tokenValue: string) {
    const tokenHash = hash(tokenValue);
    await this.prisma.mcpAccessToken.updateMany({
      where: { tokenHash },
      data: { revokedAt: new Date() },
    });
    await this.prisma.mcpRefreshToken.updateMany({
      where: { tokenHash },
      data: { revokedAt: new Date(), rotatedAt: new Date() },
    });
  }

  public async allowedInstances(connectionId: string) {
    const rows = await this.prisma.mcpConnectionInstance.findMany({
      where: { connectionId },
      include: { instance: true },
    });
    return rows.map((row) => row.instance);
  }

  public async adminConnections() {
    return this.prisma.mcpConnection.findMany({
      include: { client: true, instances: { include: { instance: true } } },
      orderBy: { createdAt: 'desc' },
    });
  }

  public async adminInstances() {
    return this.prisma.instance.findMany({
      select: {
        id: true,
        name: true,
        number: true,
        profileName: true,
        connectionStatus: true,
      },
      orderBy: { name: 'asc' },
    });
  }

  public async adminRevokeConnection(id: string) {
    return this.prisma.$transaction(async (tx) => {
      const connection = await tx.mcpConnection.update({
        where: { id },
        data: { status: 'revoked', revokedAt: new Date() },
      });

      await tx.mcpAccessToken.updateMany({
        where: { connectionId: id, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      await tx.mcpRefreshToken.updateMany({
        where: { connectionId: id, revokedAt: null },
        data: { revokedAt: new Date(), rotatedAt: new Date() },
      });

      return connection;
    });
  }

  public async adminUpdateConnection(
    id: string,
    data: { scopes?: string[]; instanceNames?: string[]; status?: string },
  ) {
    if (data.status && !['pending', 'approved', 'revoked'].includes(data.status)) {
      badRequest('Invalid MCP connection status');
    }

    const instances = data.instanceNames
      ? await this.prisma.instance.findMany({
          where: { name: { in: data.instanceNames } },
          select: { id: true, name: true },
        })
      : null;

    if (instances && instances.length !== data.instanceNames.length) {
      badRequest('One or more instances do not exist');
    }
    const scopes = data.scopes?.filter((scope) => MCP_SCOPES.includes(scope));
    if (scopes && !scopes.includes('evolution:read')) scopes.unshift('evolution:read');

    return this.prisma.$transaction(async (tx) => {
      if (instances) {
        await tx.mcpConnectionInstance.deleteMany({ where: { connectionId: id } });
        await tx.mcpConnectionInstance.createMany({
          data: instances.map((instance) => ({ connectionId: id, instanceId: instance.id })),
        });
      }

      return tx.mcpConnection.update({
        where: { id },
        data: {
          ...(scopes ? { scopes: json(scopes) } : {}),
          ...(data.status ? { status: data.status } : {}),
          ...(data.status === 'revoked' ? { revokedAt: new Date() } : {}),
          ...(data.status === 'approved' ? { revokedAt: null, approvedAt: new Date() } : {}),
        },
        include: { instances: { include: { instance: true } } },
      });
    });
  }
}
