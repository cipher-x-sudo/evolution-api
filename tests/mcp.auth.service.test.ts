import assert from 'node:assert/strict';
import { test } from 'node:test';

import { McpAuthService } from '@api/integrations/mcp/mcp.auth.service';

const makePrisma = () => {
  const client = {
    id: 'client-row',
    clientId: 'evo_client',
    clientSecretHash: null,
    clientName: 'Test agent',
    redirectUris: ['http://localhost/callback'],
    createdAt: new Date('2026-01-01T00:00:00.000Z'),
    updatedAt: new Date('2026-01-01T00:00:00.000Z'),
  };

  return {
    mcpClient: {
      create: async () => client,
      findUnique: async () => client,
    },
  } as any;
};

test('registers an OAuth client with a valid redirect URI', async () => {
  const service = new McpAuthService(makePrisma());
  const result = await service.registerClient({
    client_name: 'Test agent',
    redirect_uris: ['http://localhost/callback'],
  });

  assert.equal(result.client_name, 'Test agent');
  assert.equal(result.redirect_uris[0], 'http://localhost/callback');
  assert.match(result.client_id, /^evo_/);
});

test('rejects malformed redirect URIs', async () => {
  const service = new McpAuthService(makePrisma());

  await assert.rejects(
    () =>
      service.registerClient({
        client_name: 'Test agent',
        redirect_uris: ['not-a-url'],
      }),
    (error: any) => error?.status === 400,
  );
});

test('rejects a short administrator key without throwing from timingSafeEqual', async () => {
  const service = new McpAuthService(makePrisma());

  await assert.rejects(
    () =>
      service.approveAuthorization(
        {
          clientId: 'evo_client',
          redirectUri: 'http://localhost/callback',
          responseType: 'code',
          codeChallenge: 'challenge',
          codeChallengeMethod: 'S256',
          scope: ['evolution:read'],
        },
        ['demo'],
        ['evolution:read'],
        'x',
      ),
    (error: any) => error?.status === 401,
  );
});
