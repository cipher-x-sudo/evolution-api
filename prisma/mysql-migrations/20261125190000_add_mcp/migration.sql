-- CreateTable
CREATE TABLE `McpClient` (
    `id` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `clientSecretHash` VARCHAR(191) NULL,
    `clientName` VARCHAR(191) NOT NULL,
    `redirectUris` JSON NOT NULL,
    `createdAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `updatedAt` TIMESTAMP NOT NULL,

    UNIQUE INDEX `McpClient_clientId_key`(`clientId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpConnection` (
    `id` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'pending',
    `scopes` JSON NOT NULL,
    `createdAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `approvedAt` TIMESTAMP NULL,
    `revokedAt` TIMESTAMP NULL,
    `lastUsedAt` TIMESTAMP NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpConnectionInstance` (
    `id` VARCHAR(191) NOT NULL,
    `connectionId` VARCHAR(191) NOT NULL,
    `instanceId` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `McpConnectionInstance_connectionId_instanceId_key`(`connectionId`, `instanceId`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpAuthorizationCode` (
    `id` VARCHAR(191) NOT NULL,
    `codeHash` VARCHAR(191) NOT NULL,
    `connectionId` VARCHAR(191) NOT NULL,
    `redirectUri` VARCHAR(2048) NOT NULL,
    `codeChallenge` VARCHAR(191) NOT NULL,
    `scopes` JSON NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `usedAt` DATETIME(3) NULL,

    UNIQUE INDEX `McpAuthorizationCode_codeHash_key`(`codeHash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpAccessToken` (
    `id` VARCHAR(191) NOT NULL,
    `tokenHash` VARCHAR(191) NOT NULL,
    `connectionId` VARCHAR(191) NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `revokedAt` DATETIME(3) NULL,

    UNIQUE INDEX `McpAccessToken_tokenHash_key`(`tokenHash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpRefreshToken` (
    `id` VARCHAR(191) NOT NULL,
    `tokenHash` VARCHAR(191) NOT NULL,
    `connectionId` VARCHAR(191) NOT NULL,
    `expiresAt` DATETIME(3) NOT NULL,
    `revokedAt` DATETIME(3) NULL,
    `rotatedAt` DATETIME(3) NULL,

    UNIQUE INDEX `McpRefreshToken_tokenHash_key`(`tokenHash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpIdempotencyKey` (
    `id` VARCHAR(191) NOT NULL,
    `connectionId` VARCHAR(191) NOT NULL,
    `instanceName` VARCHAR(191) NOT NULL,
    `toolName` VARCHAR(191) NOT NULL,
    `keyHash` VARCHAR(191) NOT NULL,
    `requestHash` VARCHAR(191) NOT NULL,
    `result` JSON NULL,
    `status` VARCHAR(191) NOT NULL DEFAULT 'completed',
    `createdAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    `expiresAt` DATETIME(3) NOT NULL,

    UNIQUE INDEX `McpIdempotencyKey_connectionId_instanceName_toolName_keyHash_key`(`connectionId`, `instanceName`, `toolName`, `keyHash`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `McpAuditEvent` (
    `id` VARCHAR(191) NOT NULL,
    `connectionId` VARCHAR(191) NOT NULL,
    `clientId` VARCHAR(191) NOT NULL,
    `instanceName` VARCHAR(191) NULL,
    `toolName` VARCHAR(191) NOT NULL,
    `status` VARCHAR(191) NOT NULL,
    `durationMs` INTEGER NULL,
    `errorCode` VARCHAR(191) NULL,
    `requestHash` VARCHAR(191) NULL,
    `createdAt` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `McpConnection` ADD CONSTRAINT `McpConnection_clientId_fkey` FOREIGN KEY (`clientId`) REFERENCES `McpClient`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpConnectionInstance` ADD CONSTRAINT `McpConnectionInstance_connectionId_fkey` FOREIGN KEY (`connectionId`) REFERENCES `McpConnection`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpConnectionInstance` ADD CONSTRAINT `McpConnectionInstance_instanceId_fkey` FOREIGN KEY (`instanceId`) REFERENCES `Instance`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpAuthorizationCode` ADD CONSTRAINT `McpAuthorizationCode_connectionId_fkey` FOREIGN KEY (`connectionId`) REFERENCES `McpConnection`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpAccessToken` ADD CONSTRAINT `McpAccessToken_connectionId_fkey` FOREIGN KEY (`connectionId`) REFERENCES `McpConnection`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpRefreshToken` ADD CONSTRAINT `McpRefreshToken_connectionId_fkey` FOREIGN KEY (`connectionId`) REFERENCES `McpConnection`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpIdempotencyKey` ADD CONSTRAINT `McpIdempotencyKey_connectionId_fkey` FOREIGN KEY (`connectionId`) REFERENCES `McpConnection`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE `McpAuditEvent` ADD CONSTRAINT `McpAuditEvent_connectionId_fkey` FOREIGN KEY (`connectionId`) REFERENCES `McpConnection`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
