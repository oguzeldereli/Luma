using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Services;
using Luma.Core.Models.Auth;
using Luma.Core.Models.Services;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Services.Authorization
{
    public class TokenService : ITokenService
    {
        private readonly IClientRepository _clientRepository;
        private readonly IAuthorizeService _authorizeService;
        private readonly IAccessTokenProvider _accessTokenProvider;
        private readonly IRefreshTokenProvider _refreshTokenProvider;
        private readonly IIDTokenProvider _idTokenProvider;

        public TokenService
            (IAuthorizeService authorizeService,
            IClientRepository clientRepository,
            IAccessTokenProvider accessTokenProvider,
            IRefreshTokenProvider refreshTokenProvider,
            IIDTokenProvider idTokenProvider
            )
        {
            _authorizeService = authorizeService;
            _clientRepository = clientRepository;
            _accessTokenProvider = accessTokenProvider;
            _refreshTokenProvider = refreshTokenProvider;
            _idTokenProvider = idTokenProvider;
        }

        public async Task<OAuthServiceResponse<TokenResponseDTO>> IssueTokensFromAuthorizationCode(TokenRequestDTO request)
        {
            if (request.grant_type != "authorization_code")
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unsupported_grant_type",
                    "The grant_type provided is not supported.",
                    400, null, null, null, null);
            }

            if (!_clientRepository.ClientExists(request.client_id))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",   
                    "The client_id provided is invalid.",
                    401, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.resource) && !_clientRepository.ClientHasResource(request.client_id, request.resource))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client is not authorized to access the specified resource.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.ClientAllowsGrantType(request.client_id, request.grant_type))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unauthorized_client",
                    "The client is not authorized to use this grant type.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.scope) && !_clientRepository.ClientHasScope(request.client_id, request.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_scope",
                    "The client is not authorized for one or more of the requested scopes.",
                    400, null, null, null, null);
            }

            if (_clientRepository.ClientIsConfidential(request.client_id) && !_clientRepository.AuthenticateClient(request.client_id, request.client_secret))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.ClientHasRedirectUri(request.client_id, request.redirect_uri))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The redirect_uri provided is invalid.",
                    400, null, null, null, null);
            }

            if (string.IsNullOrWhiteSpace(request.code))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_request",
                    "The authorization code is required.",
                    400, null, null, null, null);
            }

            var authCodeResult = await _authorizeService.ValidateAndUseAuthorizationCodeAsync(request.code, request.client_id);
            if (!string.IsNullOrWhiteSpace(authCodeResult.ErrorCode))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    authCodeResult.ErrorCode,
                    authCodeResult.ErrorMessage ?? "The specified authorization code is invalid.",
                    400, null, null, null, null);
            }

            var authCode = authCodeResult.Data;
            if (authCode == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The authorization code is invalid or has already been used.",
                    400, null, null, null, null);
            }

            if (authCode.ClientId != request.client_id )
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The authorization code was not issued to the authenticated client.",
                    400, null, null, null, null);
            }

            if (authCode.RedirectUri != request.redirect_uri)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The redirect_uri does not match the one used in the authorization request.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.resource) && authCode.Resource != request.resource)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_target",
                    "The resource does not match the one used in the authorization request.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.scope))
            {
                var requestedScopes = request.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var codeScopes = authCode.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (!requestedScopes.All(rs => codeScopes.Contains(rs)))
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_scope",
                        "The requested scope exceeds the scope granted by the authorization code.",
                        400, null, null, null, null);
                }
            }

            if (!_clientRepository.ClientIsConfidential(request.client_id) && request.code_verifier == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_request",
                    "The code_verifier is required for public clients.",
                    400, null, null, null, null);
            }

            if (authCode.CodeChallengeMethod != null)
            {
                if (string.IsNullOrWhiteSpace(request.code_verifier))
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_request",
                        "The code_verifier is required for this authorization code.",
                    400, null, null, null, null);
                }

                if (authCode.CodeChallenge == null)
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_request",
                        "The authorization code does not have a code_challenge associated with it.",
                    400, null, null, null, null);
                }

                var isValidPkce = await _authorizeService.VerifyPkceCodeVerifierAsync(request.code_verifier, authCode.CodeChallenge, authCode.CodeChallengeMethod);
                if (!isValidPkce)
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_grant",
                        "The PKCE code_verifier is invalid.",
                        400, null, null, null, null);
                }
            }


            var resource = request.resource ?? authCode.Resource;
            var scope = request.scope ?? authCode.Scope;

            var (atoken, aplain) = await _accessTokenProvider.CreateForUserAsync(authCode.UserId, authCode.ClientId, resource, scope);
            var (rtoken, rplain) = await _refreshTokenProvider.CreateAsync(atoken.Id);
            var iplain = await _idTokenProvider.CreateAsync(atoken.Id, authCode.Nonce);
            var tokenResponse = new TokenResponseDTO(
                access_token: aplain,
                token_type: "Bearer",
                expires_in: (int)(atoken.ExpiresAt - atoken.CreatedAt).TotalSeconds,
                refresh_token: rplain,
                scope: atoken.Scope,
                id_token: iplain
                );

            return OAuthServiceResponse<TokenResponseDTO>.Success(tokenResponse);
        }

        public async Task<OAuthServiceResponse<TokenResponseDTO>> IssueTokensFromRefreshToken(TokenRefreshDTO request)
        {
            if (request.grant_type != "refresh_token")
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unsupported_grant_type",
                    "The grant_type provided is not supported.",
                    400, null, null, null, null);
            }

            if (string.IsNullOrWhiteSpace(request.client_id) || !_clientRepository.ClientExists(request.client_id))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    401, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.resource) && !_clientRepository.ClientHasResource(request.client_id, request.resource))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_target",
                    "The client is not authorized to access the specified resource.",
                    400, null, null, null, null);
            }

            if (!_clientRepository.ClientAllowsGrantType(request.client_id, request.grant_type))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unauthorized_client",
                    "The client is not authorized to use this grant type.",
                    400, null, null, null, null);
            }

            if (_clientRepository.ClientIsConfidential(request.client_id) && !_clientRepository.AuthenticateClient(request.client_id, request.client_secret))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    401, null, null, null, null);
            }

            if (string.IsNullOrWhiteSpace(request.refresh_token))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_request",
                    "The refresh_token is required.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.scope) && !_clientRepository.ClientHasScope(request.client_id, request.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_scope",
                    "The client is not authorized for one or more of the requested scopes.",
                    400, null, null, null, null);
            }

            var rtokenResult = await _refreshTokenProvider.ValidateAndUseTokenAsync(request.refresh_token, request.client_id);
            if (!rtokenResult.IsValid || rtokenResult.Token == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    rtokenResult.Reason ?? "The refresh token is invalid.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.resource) && request.resource != rtokenResult.Token.Aud)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_target",
                    "The resource does not match the one associated with the original token.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.scope))
            {
                var requestedScopes = request.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                var tokenScopes = rtokenResult.Token.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if (!requestedScopes.All(rs => tokenScopes.Contains(rs)))
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_scope",
                        "The requested scope exceeds the scope granted by the original token.",
                        400, null, null, null, null);
                }
            }

            var refreshToken = rtokenResult.Token;
            var resource = request.resource ?? refreshToken.Aud;
            var scope = request.scope ?? refreshToken.Scope;

            if (refreshToken.UserId == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The refresh token is not associated with a user.",
                    400, null, null, null, null);
            }

            var (atoken, aplain) = await _accessTokenProvider.CreateForUserAsync(refreshToken.UserId.Value, refreshToken.ClientId, resource, scope);
            var (newRToken, newRPlain) = await _refreshTokenProvider.CreateAsync(atoken.Id);
            var iplain = await _idTokenProvider.CreateAsync(atoken.Id);

            var tokenResponse = new TokenResponseDTO(
                access_token: aplain,
                token_type: "Bearer",
                expires_in: (int)(atoken.ExpiresAt - atoken.CreatedAt).TotalSeconds,
                refresh_token: newRPlain,
                scope: atoken.Scope,
                id_token: iplain
            );

            return OAuthServiceResponse<TokenResponseDTO>.Success(tokenResponse);
        }

        public async Task<OAuthServiceResponse<TokenResponseDTO>> IssueTokensFromClientCredentials(TokenClientCredentialsDTO request)
        {
            if (request.grant_type != "client_credentials")
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unsupported_grant_type",
                    "The grant_type provided is not supported.",
                    400, null, null, null, null);
            }

            if (string.IsNullOrWhiteSpace(request.client_id) || !_clientRepository.ClientExists(request.client_id))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.ClientIsConfidential(request.client_id))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client must be confidential to use this grant type.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.AuthenticateClient(request.client_id, request.client_secret))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.ClientAllowsGrantType(request.client_id, request.grant_type))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unauthorized_client",
                    "The client is not authorized to use this grant type.",
                    400, null, null, null, null);
            }

            var client = _clientRepository.FindClientById(request.client_id);
            if (client == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    401, null, null, null, null);
            }

            var resource = request.resource ?? client.DefaultResource;

            if (string.IsNullOrWhiteSpace(resource))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_request",
                    "The resource is required for the client_credentials grant.",
                    400, null, null, null, null);
            }

            if (!_clientRepository.ClientHasResource(request.client_id, resource))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_target",
                    "The client is not authorized to access the specified resource.",
                    400, null, null, null, null);
            }

            if (!string.IsNullOrEmpty(request.scope) &&
                !_clientRepository.ClientHasScope(request.client_id, request.scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_scope",
                    "The client is not authorized for one or more of the requested scopes.",
                    400, null, null, null, null);
            }

            // Issue access token for the client (no refresh_token or id_token for client_credentials per spec)
            var (atoken, aplain) = await _accessTokenProvider.CreateForClientAsync(
                request.client_id,
                request.resource!,
                request.scope
            );

            var tokenResponse = new TokenResponseDTO(
                access_token: aplain,
                token_type: "Bearer",
                expires_in: (int)(atoken.ExpiresAt - atoken.CreatedAt).TotalSeconds,
                refresh_token: null,
                scope: atoken.Scope,
                id_token: null
            );

            return OAuthServiceResponse<TokenResponseDTO>.Success(tokenResponse);
        }


        public async Task<OAuthServiceResponse<TokenIntrospectionResponseDTO>> IntrospectToken(TokenIntrospectionRequestDTO request)
        {
            var client = _clientRepository.FindClientById(request.client_id);
            if (client == null)
            {
                return OAuthServiceResponse<TokenIntrospectionResponseDTO>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.ClientIsConfidential(request.client_id))
            {
                return OAuthServiceResponse<TokenIntrospectionResponseDTO>.Failure(
                    "invalid_client",
                    "The client must be confidential to use this endpoint.",
                    401, null, null, null, null);
            }

            if (!_clientRepository.AuthenticateClient(request.client_id, request.client_secret))
            {
                return OAuthServiceResponse<TokenIntrospectionResponseDTO>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    401, null, null, null, null);
            }

            var atokenIntrospection = await _accessTokenProvider.IntrospectTokenAsync(request.token);
            var rTokenIntrospection = await _refreshTokenProvider.IntrospectTokenAsync(request.token);
            
            return OAuthServiceResponse<TokenIntrospectionResponseDTO>.Success(
                atokenIntrospection.active ? atokenIntrospection : rTokenIntrospection);
        }

        public async Task<OAuthServiceResponse<bool>> RevokeToken(TokenRevocationRequestDTO request)
        {
            throw new NotImplementedException();
        }
    }
}
