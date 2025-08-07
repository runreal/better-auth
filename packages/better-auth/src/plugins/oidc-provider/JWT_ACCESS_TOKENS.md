# JWT Access Tokens in OIDC Provider

## Overview

This implementation adds support for JWT access tokens in the OIDC provider plugin, which is required for compatibility with systems like Unreal Engine Horde that expect JWT Bearer tokens instead of opaque session tokens.

## Features

### 1. JWT Access Token Generation
- **Option**: `generateJWTAccessTokens: true`
- When enabled, access tokens are signed JWTs containing user claims
- Supports both RS256/EdDSA (via JWT plugin) and HS256 (via client secret)

### 2. Flexible Audience Configuration
- **Global Option**: `accessTokenAudience` - sets default audience for all clients
- **Per-Client Override**: `client.metadata.audience` - allows client-specific audiences
- **Fallback**: Uses auth server's base URL if no audience is specified

### 3. Token Storage Strategy
- **JWT Tokens**: Only the SHA-256 hash is stored in the database (as hex string)
- **Opaque Tokens**: Full token is stored (existing behavior)
- This allows validation while minimizing database storage

## Configuration Examples

### Basic Setup with JWT Access Tokens
```typescript
import { betterAuth } from "better-auth";
import { oidcProvider } from "better-auth/plugins/oidc-provider";

const auth = betterAuth({
  plugins: [
    oidcProvider({
      generateJWTAccessTokens: true,
      accessTokenAudience: "https://api.example.com",
      // ... other options
    })
  ]
});
```

### With JWT Plugin for RS256 Signing
```typescript
import { betterAuth } from "better-auth";
import { oidcProvider } from "better-auth/plugins/oidc-provider";
import { jwt } from "better-auth/plugins/jwt";

const auth = betterAuth({
  plugins: [
    jwt({
      jwt: {
        issuer: "https://auth.example.com"
      }
    }),
    oidcProvider({
      generateJWTAccessTokens: true,
      useJWTPlugin: true, // Use RS256/EdDSA instead of HS256
      accessTokenAudience: "https://api.example.com",
    })
  ]
});
```

### Client-Specific Audience
```typescript
// When registering a client
const client = {
  clientId: "my-app",
  clientSecret: "secret",
  metadata: {
    audience: "https://specific-api.example.com" // Overrides global setting
  },
  // ... other client config
};
```

## Token Validation

### For Resource Servers

1. **RS256/EdDSA Tokens** (with JWT plugin):
   - Validate using the JWKS endpoint at `/.well-known/jwks`
   - Standard JWT validation libraries can be used

2. **HS256 Tokens** (default):
   - Validate using the client secret
   - Only the client and auth server have the secret

### Example Token Payload
```json
{
  "sub": "user-id",
  "aud": "https://api.example.com",
  "iss": "https://auth.example.com",
  "client_id": "my-app",
  "email": "user@example.com",
  "name": "John Doe",
  "scope": "openid profile email",
  "jti": "unique-token-id",
  "iat": 1234567890,
  "exp": 1234571490
}
```

## Compatibility

This implementation maintains full backward compatibility:
- Existing deployments using opaque tokens continue to work
- The `generateJWTAccessTokens` option defaults to `false`
- All existing OIDC flows remain unchanged

## Security Considerations

1. **Token Storage**: JWT access tokens are stored as SHA-256 hashes to prevent token leakage if the database is compromised
2. **Audience Validation**: Resource servers MUST validate the `aud` claim
3. **Expiration**: Default expiration is 1 hour (configurable via `accessTokenExpiresIn`)
4. **Client Secrets**: Must be kept secure when using HS256 signing