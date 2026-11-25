# Evolution API MCP

Evolution API exposes an optional remote MCP server on the hostname configured by `MCP_PUBLIC_URL`.

## Enable it

```env
MCP_ENABLED=true
MCP_PUBLIC_URL=https://mcp-evolution.example.com
```

Apply the database migration for the selected provider before starting the API:

```bash
DATABASE_PROVIDER=postgresql npm run db:deploy
```

`psql_bouncer` uses the PostgreSQL migrations. MySQL uses the matching MySQL migration directory.

## OAuth flow

1. `POST /register` with `client_name`, `redirect_uris`, and optional `token_endpoint_auth_method` (`none` or `client_secret_post`).
2. Build a PKCE S256 authorization request for `/authorize`.
3. Approve it in the browser form with the administrator API key, or provide that key in the `apikey` or `x-admin-api-key` header. The approval request must include `instance_names` and requested `scope`.
4. Exchange the returned code at `/token`.
5. Send the access token as `Authorization: Bearer <token>` to `/mcp`.

OAuth metadata is available at:

- `/.well-known/oauth-authorization-server`
- `/.well-known/oauth-protected-resource`

The MCP endpoint is stateless Streamable HTTP. Connections are restricted to the approved instance allowlist and OAuth scopes.

## Admin endpoints

These endpoints use the existing global `apikey` header:

- `GET /mcp/admin/instances`
- `GET /mcp/admin/connections`
- `PATCH /mcp/admin/connections/:id`
- `POST /mcp/admin/connections/:id/revoke`

## Available tools

Read tools:

- `list_instances`
- `get_instance_status`
- `list_contacts`
- `list_chats`
- `list_messages`
- `list_groups`
- `get_group`

Write tools:

- `send_text_message`
- `send_media_message`
- `send_reaction`
- `send_poll`
- `set_presence`
- `create_group`
- `update_group_participants`

Write tools require a stable `idempotencyKey`. Media accepts HTTPS URLs or bounded base64 data URLs.
