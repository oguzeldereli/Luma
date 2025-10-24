using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Services;
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
                    null);
            }

            if (!_clientRepository.ClientExists(request.client_id))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    null);
            }

            if (!_clientRepository.ClientAllowsGrantType(request.client_id, request.grant_type))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unauthorized_client",
                    "The client is not authorized to use this grant type.",
                    null);
            }

            if (!_clientRepository.AuthenticateClient(request.client_id, request.client_secret))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    null);
            }

            if (!_clientRepository.ClientHasRedirectUri(request.client_id, request.redirect_uri))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The redirect_uri provided is invalid.",
                    null);
            }

            if (string.IsNullOrWhiteSpace(request.code))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_request",
                    "The authorization code is required.",
                    null);
            }

            var authCodeResult = await _authorizeService.ValidateAndUseAuthorizationCodeAsync(request.code, request.client_id);
            if (!string.IsNullOrWhiteSpace(authCodeResult.ErrorCode))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    authCodeResult.ErrorCode,
                    authCodeResult.ErrorMessage ?? "The specified authorization code is invalid.",
                    null);
            }

            var authCode = authCodeResult.Data;
            if (authCode == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The authorization code is invalid or has already been used.",
                    null);
            }

            if (authCode.ClientId != request.client_id )
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The authorization code was not issued to the authenticated client.",
                    null);
            }

            if (authCode.RedirectUri != request.redirect_uri)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    "The redirect_uri does not match the one used in the authorization request.",
                    null);
            }

            if (authCode.CodeChallengeMethod != null)
            {
                if (string.IsNullOrWhiteSpace(request.code_verifier))
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_request",
                        "The code_verifier is required for this authorization code.",
                        null);
                }

                if (authCode.CodeChallenge == null)
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_request",
                        "The authorization code does not have a code_challenge associated with it.",
                        null);
                }

                var isValidPkce = await _authorizeService.VerifyPkceCodeVerifierAsync(request.code_verifier, authCode.CodeChallenge, authCode.CodeChallengeMethod);
                if (!isValidPkce)
                {
                    return OAuthServiceResponse<TokenResponseDTO>.Failure(
                        "invalid_grant",
                        "The PKCE code_verifier is invalid.",
                        null);
                }
            }

            var (atoken, aplain) = await _accessTokenProvider.CreateAsync(authCode.UserId, authCode.ClientId, authCode.Scope);
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
                    null);
            }

            if (string.IsNullOrWhiteSpace(request.client_id) || !_clientRepository.ClientExists(request.client_id))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    null);
            }

            if (!_clientRepository.ClientAllowsGrantType(request.client_id, request.grant_type))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "unauthorized_client",
                    "The client is not authorized to use this grant type.",
                    null);
            }

            if (!_clientRepository.AuthenticateClient(request.client_id, request.client_secret))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    null);
            }

            if (string.IsNullOrWhiteSpace(request.refresh_token))
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_request",
                    "The refresh_token is required.",
                    null);
            }

            var rtokenResult = await _refreshTokenProvider.ValidateAndUseTokenAsync(request.refresh_token, request.client_id);
            if (!rtokenResult.IsValid || rtokenResult.Token == null)
            {
                return OAuthServiceResponse<TokenResponseDTO>.Failure(
                    "invalid_grant",
                    rtokenResult.Reason ?? "The refresh token is invalid.",
                    null);
            }

            var refreshToken = rtokenResult.Token;

            var (atoken, aplain) = await _accessTokenProvider.CreateAsync(refreshToken.UserId, refreshToken.Aud, refreshToken.Scope);
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
    }
}
