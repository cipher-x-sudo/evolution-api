-- CreateTable
CREATE TABLE "McpClient" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "clientSecretHash" TEXT,
    "clientName" VARCHAR(255) NOT NULL,
    "redirectUris" JSONB NOT NULL,
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP NOT NULL,

    CONSTRAINT "McpClient_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpConnection" (
    "id" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "status" VARCHAR(30) NOT NULL DEFAULT 'pending',
    "scopes" JSONB NOT NULL,
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "approvedAt" TIMESTAMP,
    "revokedAt" TIMESTAMP,
    "lastUsedAt" TIMESTAMP,

    CONSTRAINT "McpConnection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpConnectionInstance" (
    "id" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "instanceId" TEXT NOT NULL,

    CONSTRAINT "McpConnectionInstance_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpAuthorizationCode" (
    "id" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "redirectUri" TEXT NOT NULL,
    "codeChallenge" TEXT NOT NULL,
    "scopes" JSONB NOT NULL,
    "expiresAt" TIMESTAMP NOT NULL,
    "usedAt" TIMESTAMP,

    CONSTRAINT "McpAuthorizationCode_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpAccessToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP NOT NULL,
    "revokedAt" TIMESTAMP,

    CONSTRAINT "McpAccessToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpRefreshToken" (
    "id" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP NOT NULL,
    "revokedAt" TIMESTAMP,
    "rotatedAt" TIMESTAMP,

    CONSTRAINT "McpRefreshToken_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpIdempotencyKey" (
    "id" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "instanceName" VARCHAR(255) NOT NULL,
    "toolName" VARCHAR(100) NOT NULL,
    "keyHash" VARCHAR(128) NOT NULL,
    "requestHash" VARCHAR(128) NOT NULL,
    "result" JSONB,
    "status" VARCHAR(30) NOT NULL DEFAULT 'completed',
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expiresAt" TIMESTAMP NOT NULL,

    CONSTRAINT "McpIdempotencyKey_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "McpAuditEvent" (
    "id" TEXT NOT NULL,
    "connectionId" TEXT NOT NULL,
    "clientId" TEXT NOT NULL,
    "instanceName" VARCHAR(255),
    "toolName" VARCHAR(100) NOT NULL,
    "status" VARCHAR(30) NOT NULL,
    "durationMs" INTEGER,
    "errorCode" VARCHAR(100),
    "requestHash" VARCHAR(128),
    "createdAt" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "McpAuditEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "McpClient_clientId_key" ON "McpClient"("clientId");
CREATE INDEX "McpConnection_clientId_idx" ON "McpConnection"("clientId");
CREATE INDEX "McpConnection_status_idx" ON "McpConnection"("status");
CREATE UNIQUE INDEX "McpConnectionInstance_connectionId_instanceId_key" ON "McpConnectionInstance"("connectionId", "instanceId");
CREATE INDEX "McpConnectionInstance_instanceId_idx" ON "McpConnectionInstance"("instanceId");
CREATE UNIQUE INDEX "McpAuthorizationCode_codeHash_key" ON "McpAuthorizationCode"("codeHash");
CREATE INDEX "McpAuthorizationCode_connectionId_idx" ON "McpAuthorizationCode"("connectionId");
CREATE INDEX "McpAuthorizationCode_expiresAt_idx" ON "McpAuthorizationCode"("expiresAt");
CREATE UNIQUE INDEX "McpAccessToken_tokenHash_key" ON "McpAccessToken"("tokenHash");
CREATE INDEX "McpAccessToken_connectionId_idx" ON "McpAccessToken"("connectionId");
CREATE INDEX "McpAccessToken_expiresAt_idx" ON "McpAccessToken"("expiresAt");
CREATE UNIQUE INDEX "McpRefreshToken_tokenHash_key" ON "McpRefreshToken"("tokenHash");
CREATE INDEX "McpRefreshToken_connectionId_idx" ON "McpRefreshToken"("connectionId");
CREATE INDEX "McpRefreshToken_expiresAt_idx" ON "McpRefreshToken"("expiresAt");
CREATE UNIQUE INDEX "McpIdempotencyKey_connectionId_instanceName_toolName_keyHash_key" ON "McpIdempotencyKey"("connectionId", "instanceName", "toolName", "keyHash");
CREATE INDEX "McpIdempotencyKey_expiresAt_idx" ON "McpIdempotencyKey"("expiresAt");
CREATE INDEX "McpAuditEvent_connectionId_createdAt_idx" ON "McpAuditEvent"("connectionId", "createdAt");
CREATE INDEX "McpAuditEvent_clientId_createdAt_idx" ON "McpAuditEvent"("clientId", "createdAt");

-- AddForeignKey
ALTER TABLE "McpConnection" ADD CONSTRAINT "McpConnection_clientId_fkey" FOREIGN KEY ("clientId") REFERENCES "McpClient"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpConnectionInstance" ADD CONSTRAINT "McpConnectionInstance_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "McpConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpConnectionInstance" ADD CONSTRAINT "McpConnectionInstance_instanceId_fkey" FOREIGN KEY ("instanceId") REFERENCES "Instance"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpAuthorizationCode" ADD CONSTRAINT "McpAuthorizationCode_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "McpConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpAccessToken" ADD CONSTRAINT "McpAccessToken_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "McpConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpRefreshToken" ADD CONSTRAINT "McpRefreshToken_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "McpConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpIdempotencyKey" ADD CONSTRAINT "McpIdempotencyKey_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "McpConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "McpAuditEvent" ADD CONSTRAINT "McpAuditEvent_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "McpConnection"("id") ON DELETE CASCADE ON UPDATE CASCADE;
