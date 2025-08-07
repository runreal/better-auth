import type { GenericEndpointContext, User } from "../../types";
import type { Client, OIDCOptions } from "./types";
import { SignJWT } from "jose";
import { generateRandomString } from "../../crypto";
import { APIError } from "../../api";
import { getJwtToken } from "../jwt/sign";
import type { jwt } from "../jwt";

/**
 * Get the JWT plugin from the context
 */
export const getJwtPlugin = (ctx: GenericEndpointContext) => {
	return ctx.context.options.plugins?.find(
		(plugin) => plugin.id === "jwt",
	) as ReturnType<typeof jwt>;
};

/**
 * Generate a JWT access token for OIDC flows
 * 
 * This function supports two modes:
 * 1. Using the JWT plugin (RS256/EdDSA) - for production use with proper key management
 * 2. Using HS256 with client secret - for simpler deployments
 * 
 * @param ctx - The generic endpoint context
 * @param user - The authenticated user
 * @param client - The OAuth client
 * @param scopes - The requested scopes
 * @param expiresIn - Token expiration time in seconds
 * @param options - OIDC options including JWT configuration
 * @returns The signed JWT access token
 */
export async function generateJWTAccessToken(
	ctx: GenericEndpointContext,
	user: User & Record<string, any>,
	client: Client,
	scopes: string[],
	expiresIn: number,
	options: OIDCOptions & { useJWTPlugin?: boolean },
): Promise<string> {
	// Determine the audience claim
	// Priority: client metadata > global option > base URL
	const audience = client.metadata?.audience || 
		options.accessTokenAudience || 
		ctx.context.options.baseURL;

	// Determine the issuer
	let issuer = ctx.context.options.baseURL;
	if (options.useJWTPlugin) {
		const jwtPlugin = getJwtPlugin(ctx);
		if (jwtPlugin?.options?.jwt?.issuer) {
			issuer = jwtPlugin.options.jwt.issuer;
		}
	}

	// Build the base payload
	const payload = {
		sub: user.id,
		aud: audience,
		iss: issuer,
		client_id: client.clientId,
		email: user.email,
		name: user.name,
		scope: scopes.join(" "),
		jti: generateRandomString(16, "a-z", "A-Z", "0-9"),
	};

	// Add custom claims if provided
	if (options.getAdditionalUserInfoClaim) {
		const additionalClaims = await options.getAdditionalUserInfoClaim(
			user,
			scopes,
		);
		Object.assign(payload, additionalClaims);
	}

	const expirationTime = Math.floor(Date.now() / 1000) + expiresIn;

	// Use JWT plugin if enabled
	if (options.useJWTPlugin) {
		const jwtPlugin = getJwtPlugin(ctx);
		if (!jwtPlugin) {
			throw new APIError("INTERNAL_SERVER_ERROR", {
				error_description: "JWT plugin is not enabled",
				error: "internal_server_error",
			});
		}

		return await getJwtToken(
			{
				...ctx,
				context: {
					...ctx.context,
					session: {
						session: {
							id: generateRandomString(32, "a-z", "A-Z"),
							createdAt: new Date(),
							updatedAt: new Date(),
							userId: user.id,
							expiresAt: new Date(Date.now() + expiresIn * 1000),
							token: "", // temporary placeholder
							ipAddress: ctx.request?.headers.get("x-forwarded-for"),
						},
						user,
					},
				},
			},
			{
				...jwtPlugin.options,
				jwt: {
					...jwtPlugin.options?.jwt,
					getSubject: () => user.id,
					audience: audience,
					issuer: issuer,
					expirationTime,
					definePayload: () => payload,
				},
			},
		);
	}

	// Use HS256 with client secret for simpler deployments
	if (!client.clientSecret) {
		throw new APIError("INTERNAL_SERVER_ERROR", {
			error_description: "Client secret is required for HS256 signing",
			error: "internal_server_error",
		});
	}

	return await new SignJWT(payload)
		.setProtectedHeader({ alg: "HS256" })
		.setIssuedAt()
		.setExpirationTime(expirationTime)
		.sign(new TextEncoder().encode(client.clientSecret));
}

/**
 * Validate a JWT access token
 * 
 * @param token - The JWT access token to validate
 * @param client - The OAuth client
 * @param options - OIDC options
 * @returns The decoded payload if valid
 */
export async function validateJWTAccessToken(
	token: string,
	client: Client,
	options: OIDCOptions & { useJWTPlugin?: boolean },
): Promise<any> {
	// For JWT plugin tokens (RS256/EdDSA), validation should be done
	// by the resource server using the JWKS endpoint
	// This is just a placeholder for future implementation
	
	// For HS256 tokens, we would verify with the client secret
	// but this is typically done by the resource server, not the auth server
	
	throw new APIError("NOT_IMPLEMENTED", {
		error_description: "JWT access token validation not implemented",
		error: "internal_server_error",
	});
}