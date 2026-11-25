import { ChatController } from '@api/controllers/chat.controller';
import { GroupController } from '@api/controllers/group.controller';
import { SendMessageController } from '@api/controllers/sendMessage.controller';
import { PrismaRepository } from '@api/repository/repository.service';
import { WAMonitoringService } from '@api/services/monitor.service';
import { configService, Mcp } from '@config/env.config';
import { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { CallToolResult, ToolAnnotations } from '@modelcontextprotocol/sdk/types.js';
import { createHash } from 'crypto';
import { Request, Response } from 'express';
import { z } from 'zod';

import { McpAuthService } from './mcp.auth.service';

type ToolExtra = { authInfo?: AuthInfo };

const sha256 = (value: unknown) => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const safeJson = (value: unknown) => JSON.parse(JSON.stringify(value ?? null));

export class McpService {
  private readonly config = configService.get<Mcp>('MCP');
  private readonly authService: McpAuthService;
  private readonly rateWindows = new Map<string, { start: number; count: number }>();

  constructor(
    private readonly prisma: PrismaRepository,
    private readonly waMonitor: WAMonitoringService,
    private readonly sendMessageController: SendMessageController,
    private readonly chatController: ChatController,
    private readonly groupController: GroupController,
  ) {
    this.authService = new McpAuthService(prisma);
  }

  public get auth() {
    return this.authService;
  }

  public isEnabled() {
    return this.config.ENABLED;
  }

  public isPublicHost(req: Request) {
    if (!this.config.PUBLIC_URL) return false;
    try {
      return new URL(this.config.PUBLIC_URL).hostname === req.hostname;
    } catch {
      return false;
    }
  }

  public async handleMcp(req: Request, res: Response) {
    if (!this.isEnabled() || !this.isPublicHost(req)) return res.status(404).json({ error: 'Not found' });

    const authorization = req.get('authorization') || '';
    if (!/^Bearer\s+/i.test(authorization)) {
      res.set(
        'WWW-Authenticate',
        `Bearer resource_metadata="${this.auth.publicUrl()}/.well-known/oauth-protected-resource"`,
      );
      return res.status(401).json({ error: 'Unauthorized' });
    }

    let authInfo: AuthInfo;
    try {
      authInfo = await this.auth.verifyAccessToken(authorization.replace(/^Bearer\s+/i, '').trim());
    } catch {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    try {
      const mcp = this.createServer();
      const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
      await mcp.connect(transport);
      (req as any).auth = authInfo;
      res.on('close', () => {
        transport.close().catch(() => undefined);
        mcp.close().catch(() => undefined);
      });
      await transport.handleRequest(req as any, res as any, req.body);
    } catch {
      if (!res.headersSent) {
        return res.status(500).json({ error: 'MCP request failed' });
      }
    }
  }

  private createServer() {
    const server: any = new McpServer(
      { name: 'Evolution API MCP', version: '2.3.8' },
      {
        instructions:
          'Use list_instances first. Every other tool requires an explicit instanceName. Do not retry a send without reusing the same idempotencyKey.',
        maxToolInputElements: 200,
      },
    );

    const readAnnotations: ToolAnnotations = {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    };
    const writeAnnotations: ToolAnnotations = {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    };

    server.registerTool(
      'list_instances',
      {
        description: 'List Evolution instances approved for this MCP connection.',
        annotations: readAnnotations,
      },
      async (_args, extra) =>
        this.runTool('list_instances', extra, 'evolution:read', async () => this.listInstances(extra)),
    );

    server.registerTool(
      'get_instance_status',
      {
        description: 'Read the connection status of an approved Evolution instance.',
        inputSchema: { instanceName: z.string().min(1) },
        annotations: readAnnotations,
      },
      async ({ instanceName }, extra) =>
        this.runTool('get_instance_status', extra, 'evolution:read', () => this.getInstanceStatus(extra, instanceName)),
    );

    server.registerTool(
      'list_contacts',
      {
        description: 'List contacts for an approved instance with bounded pagination.',
        inputSchema: {
          instanceName: z.string().min(1),
          offset: z.number().int().min(0).max(100000).optional(),
          page: z.number().int().min(1).max(10000).optional(),
        },
        annotations: readAnnotations,
      },
      async ({ instanceName, offset, page }, extra) =>
        this.runTool('list_contacts', extra, 'evolution:read', () =>
          this.readPaged(extra, instanceName, () =>
            this.chatController.fetchContacts({ instanceName }, { offset, page, sort: 'desc' } as any),
          ),
        ),
    );

    server.registerTool(
      'list_chats',
      {
        description: 'List chats for an approved instance with bounded pagination.',
        inputSchema: {
          instanceName: z.string().min(1),
          offset: z.number().int().min(0).max(100000).optional(),
          page: z.number().int().min(1).max(10000).optional(),
        },
        annotations: readAnnotations,
      },
      async ({ instanceName, offset, page }, extra) =>
        this.runTool('list_chats', extra, 'evolution:read', () =>
          this.readPaged(extra, instanceName, () =>
            this.chatController.fetchChats({ instanceName }, { offset, page, sort: 'desc' } as any),
          ),
        ),
    );

    server.registerTool(
      'list_messages',
      {
        description: 'List stored messages for an approved instance with bounded pagination.',
        inputSchema: {
          instanceName: z.string().min(1),
          offset: z.number().int().min(0).max(100000).optional(),
          page: z.number().int().min(1).max(10000).optional(),
        },
        annotations: readAnnotations,
      },
      async ({ instanceName, offset, page }, extra) =>
        this.runTool('list_messages', extra, 'evolution:read', () =>
          this.readPaged(extra, instanceName, () =>
            this.chatController.fetchMessages({ instanceName }, { offset, page, sort: 'desc' } as any),
          ),
        ),
    );

    server.registerTool(
      'list_groups',
      {
        description: 'List groups for an approved instance.',
        inputSchema: { instanceName: z.string().min(1) },
        annotations: readAnnotations,
      },
      async ({ instanceName }, extra) =>
        this.runTool('list_groups', extra, 'evolution:group', async () => {
          await this.authorize(extra, instanceName, 'evolution:group', 'read');
          this.rate(extra, instanceName, 'read');
          return this.groupController.fetchAllGroups({ instanceName }, { getParticipants: 'false' });
        }),
    );

    server.registerTool(
      'get_group',
      {
        description: 'Read group metadata and participants.',
        inputSchema: { instanceName: z.string().min(1), groupJid: z.string().min(1) },
        annotations: readAnnotations,
      },
      async ({ instanceName, groupJid }, extra) =>
        this.runTool('get_group', extra, 'evolution:group', async () => {
          await this.authorize(extra, instanceName, 'evolution:group', 'read');
          this.rate(extra, instanceName, 'read');
          return this.groupController.findGroupInfo({ instanceName }, { groupJid });
        }),
    );

    server.registerTool(
      'send_text_message',
      {
        description: 'Send one text message. Always provide a stable idempotencyKey.',
        inputSchema: {
          instanceName: z.string().min(1),
          to: z.string().min(3).max(100),
          text: z.string().min(1).max(65536),
          idempotencyKey: z.string().min(8).max(200),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, to, text, idempotencyKey }, extra) =>
        this.runTool('send_text_message', extra, 'evolution:message', () =>
          this.writeOnce(extra, instanceName, 'send_text_message', idempotencyKey, { to, text }, () =>
            this.sendMessageController.sendText({ instanceName }, { number: to, text }),
          ),
        ),
    );

    server.registerTool(
      'send_media_message',
      {
        description: 'Send image, document, video, audio, or PTV media from an HTTPS URL or bounded base64.',
        inputSchema: {
          instanceName: z.string().min(1),
          to: z.string().min(3).max(100),
          media: z.string().min(1),
          mediatype: z.enum(['image', 'document', 'video', 'audio', 'ptv']),
          mimetype: z.string().max(100).optional(),
          caption: z.string().max(65536).optional(),
          fileName: z.string().max(255).optional(),
          idempotencyKey: z.string().min(8).max(200),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, to, media, mediatype, mimetype, caption, fileName, idempotencyKey }, extra) =>
        this.runTool('send_media_message', extra, 'evolution:message', () =>
          this.writeOnce(
            extra,
            instanceName,
            'send_media_message',
            idempotencyKey,
            { to, media, mediatype, mimetype, caption, fileName },
            () => {
              this.validateMedia(media);
              return this.sendMessageController.sendMedia(
                { instanceName },
                { number: to, media, mediatype, mimetype, caption, fileName },
              );
            },
          ),
        ),
    );

    server.registerTool(
      'send_reaction',
      {
        description: 'React to an existing WhatsApp message.',
        inputSchema: {
          instanceName: z.string().min(1),
          remoteJid: z.string().min(3),
          messageId: z.string().min(1),
          fromMe: z.boolean(),
          reaction: z.string().max(16),
          idempotencyKey: z.string().min(8).max(200),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, remoteJid, messageId, fromMe, reaction, idempotencyKey }, extra) =>
        this.runTool('send_reaction', extra, 'evolution:message', () =>
          this.writeOnce(
            extra,
            instanceName,
            'send_reaction',
            idempotencyKey,
            { remoteJid, messageId, fromMe, reaction },
            () =>
              this.sendMessageController.sendReaction(
                { instanceName },
                { key: { remoteJid, id: messageId, fromMe }, reaction },
              ),
          ),
        ),
    );

    server.registerTool(
      'send_poll',
      {
        description: 'Send a poll to a WhatsApp contact or group.',
        inputSchema: {
          instanceName: z.string().min(1),
          to: z.string().min(3).max(100),
          name: z.string().min(1).max(255),
          values: z.array(z.string().min(1).max(255)).min(2).max(12),
          selectableCount: z.number().int().min(1).max(12),
          idempotencyKey: z.string().min(8).max(200),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, to, name, values, selectableCount, idempotencyKey }, extra) =>
        this.runTool('send_poll', extra, 'evolution:message', () =>
          this.writeOnce(extra, instanceName, 'send_poll', idempotencyKey, { to, name, values, selectableCount }, () =>
            this.sendMessageController.sendPoll({ instanceName }, { number: to, name, values, selectableCount }),
          ),
        ),
    );

    server.registerTool(
      'set_presence',
      {
        description: 'Set online, offline, composing, recording, or paused presence.',
        inputSchema: {
          instanceName: z.string().min(1),
          presence: z.enum(['available', 'unavailable', 'composing', 'recording', 'paused']),
          to: z.string().optional(),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, presence, to }, extra) =>
        this.runTool('set_presence', extra, 'evolution:message', async () => {
          await this.authorize(extra, instanceName, 'evolution:message', 'write');
          this.rate(extra, instanceName, 'write');
          return this.waMonitor.waInstances[instanceName].setPresence({ number: to || '', presence, delay: 0 } as any);
        }),
    );

    server.registerTool(
      'create_group',
      {
        description: 'Create a WhatsApp group.',
        inputSchema: {
          instanceName: z.string().min(1),
          subject: z.string().min(1).max(255),
          participants: z.array(z.string().min(3)).min(1).max(256),
          description: z.string().max(1024).optional(),
          idempotencyKey: z.string().min(8).max(200),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, subject, participants, description, idempotencyKey }, extra) =>
        this.runTool('create_group', extra, 'evolution:group', () =>
          this.writeOnce(
            extra,
            instanceName,
            'create_group',
            idempotencyKey,
            { subject, participants, description },
            () => this.groupController.createGroup({ instanceName }, { subject, participants, description }),
          ),
        ),
    );

    server.registerTool(
      'update_group_participants',
      {
        description: 'Add, remove, promote, or demote group participants.',
        inputSchema: {
          instanceName: z.string().min(1),
          groupJid: z.string().min(1),
          action: z.enum(['add', 'remove', 'promote', 'demote']),
          participants: z.array(z.string().min(3)).min(1).max(256),
          idempotencyKey: z.string().min(8).max(200),
        },
        annotations: writeAnnotations,
      },
      async ({ instanceName, groupJid, action, participants, idempotencyKey }, extra) =>
        this.runTool('update_group_participants', extra, 'evolution:group', () =>
          this.writeOnce(
            extra,
            instanceName,
            'update_group_participants',
            idempotencyKey,
            { groupJid, action, participants },
            () => this.groupController.updateGParticipate({ instanceName }, { groupJid, action, participants }),
          ),
        ),
    );

    return server;
  }

  private async listInstances(extra: ToolExtra) {
    const connectionId = this.connectionId(extra);
    this.rate(extra, '*', 'read');
    const rows = await this.auth.allowedInstances(connectionId);
    return rows.map((instance) => ({
      name: instance.name,
      id: instance.id,
      number: instance.number,
      profileName: instance.profileName,
      connectionStatus: this.waMonitor.waInstances[instance.name]?.connectionStatus?.state || instance.connectionStatus,
    }));
  }

  private async getInstanceStatus(extra: ToolExtra, instanceName: string) {
    await this.authorize(extra, instanceName, 'evolution:read', 'read');
    this.rate(extra, instanceName, 'read');
    const instance = this.waMonitor.waInstances[instanceName];
    return {
      instanceName,
      state: instance?.connectionStatus?.state || 'close',
      number: instance?.number || null,
      profileName: instance?.profileName || null,
    };
  }

  private async readPaged(extra: ToolExtra, instanceName: string, handler: () => Promise<unknown>) {
    await this.authorize(extra, instanceName, 'evolution:read', 'read');
    this.rate(extra, instanceName, 'read');
    return handler();
  }

  private async authorize(extra: ToolExtra, instanceName: string, scope: string, mode: 'read' | 'write') {
    const auth = extra.authInfo;
    const connectionId = this.connectionId(extra);
    if (!auth?.scopes?.includes(scope)) throw new Error('permission_denied');
    if (!connectionId || !instanceName) throw new Error('invalid_instance');

    const connection = await this.prisma.mcpConnection.findUnique({
      where: { id: connectionId },
      include: { instances: { include: { instance: true } } },
    });
    const allowed = connection?.instances.some((row) => row.instance.name === instanceName);
    if (!allowed) throw new Error('instance_not_allowed');
    if (mode === 'write' && connection.status !== 'approved') throw new Error('connection_not_approved');
  }

  private async writeOnce(
    extra: ToolExtra,
    instanceName: string,
    toolName: string,
    idempotencyKey: string,
    payload: unknown,
    handler: () => Promise<unknown>,
  ) {
    await this.authorize(
      extra,
      instanceName,
      toolName === 'create_group' || toolName.includes('group') ? 'evolution:group' : 'evolution:message',
      'write',
    );
    this.rate(extra, instanceName, 'write');

    const connectionId = this.connectionId(extra);
    const requestHash = sha256(payload);
    const keyHash = sha256(idempotencyKey);
    const existing = await this.prisma.mcpIdempotencyKey.findUnique({
      where: {
        connectionId_instanceName_toolName_keyHash: {
          connectionId,
          instanceName,
          toolName,
          keyHash,
        },
      },
    });
    if (existing && existing.expiresAt.getTime() > Date.now()) {
      if (existing.requestHash !== requestHash) throw new Error('idempotency_conflict');
      return existing.result;
    }

    const result = safeJson(await handler());
    await this.prisma.mcpIdempotencyKey.upsert({
      where: {
        connectionId_instanceName_toolName_keyHash: {
          connectionId,
          instanceName,
          toolName,
          keyHash,
        },
      },
      create: {
        connectionId,
        instanceName,
        toolName,
        keyHash,
        requestHash,
        result,
        expiresAt: new Date(Date.now() + 86400000),
      },
      update: { requestHash, result, expiresAt: new Date(Date.now() + 86400000) },
    });
    return result;
  }

  private connectionId(extra: ToolExtra) {
    const value = extra?.authInfo?.extra?.connectionId;
    if (typeof value !== 'string') throw new Error('unauthorized');
    return value;
  }

  private rate(extra: ToolExtra, instanceName: string, mode: 'read' | 'write') {
    const connectionId = this.connectionId(extra);
    const key = `${connectionId}:${instanceName}:${mode}`;
    const now = Date.now();
    const current = this.rateWindows.get(key);
    const limit = mode === 'write' ? this.config.SEND_RATE_LIMIT : this.config.READ_RATE_LIMIT;
    if (!current || now - current.start >= 60000) {
      this.rateWindows.set(key, { start: now, count: 1 });
      return;
    }
    current.count += 1;
    if (current.count > limit) throw new Error('rate_limited');
  }

  private validateMedia(media: string) {
    if (/^https:\/\//i.test(media)) return;
    if (/^data:[^;]+;base64,/i.test(media)) {
      const encoded = media.slice(media.indexOf(',') + 1);
      if (Buffer.byteLength(encoded, 'base64') > this.config.MAX_MEDIA_BYTES) throw new Error('media_too_large');
      return;
    }
    throw new Error('media_must_be_https_url_or_base64');
  }

  private async runTool(
    toolName: string,
    extra: ToolExtra,
    scope: string,
    handler: () => Promise<unknown>,
  ): Promise<CallToolResult> {
    const started = Date.now();
    const connectionId = extra.authInfo?.extra?.connectionId;
    const clientId = extra.authInfo?.clientId || 'unknown';
    try {
      if (!extra.authInfo?.scopes?.includes(scope)) throw new Error('permission_denied');
      const result = await handler();
      if (typeof connectionId === 'string') {
        await this.audit(connectionId, clientId, toolName, 'success', Date.now() - started);
      }
      return { content: [{ type: 'text', text: JSON.stringify(result) }] };
    } catch (error) {
      const errorCode = error instanceof Error ? error.message : 'operation_failed';
      if (typeof connectionId === 'string') {
        await this.audit(connectionId, clientId, toolName, 'error', Date.now() - started, errorCode);
      }
      return {
        isError: true,
        content: [{ type: 'text', text: JSON.stringify({ error: errorCode }) }],
      };
    }
  }

  private async audit(
    connectionId: string,
    clientId: string,
    toolName: string,
    status: string,
    durationMs: number,
    errorCode?: string,
  ) {
    try {
      await this.prisma.mcpAuditEvent.create({
        data: { connectionId, clientId, toolName, status, durationMs, errorCode },
      });
    } catch {
      // Auditing must not break an otherwise successful WhatsApp operation.
    }
  }
}
