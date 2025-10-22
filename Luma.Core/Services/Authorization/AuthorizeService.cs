using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authorization;
using Luma.Core.Interfaces.Services;
using Luma.Core.Models.Auth;
using Luma.Core.Models.Services;
using Luma.Core.Options;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Services.Authorization
{
    public class AuthorizeService : IAuthorizeService
    {
        private readonly IClientRepository _clientRepository;
        private readonly IAuthorizationCodeStateProvider _authorizationCodeStateProvider;
        private readonly IAuthorizationCodeProvider _authorizationCodeProvider;
        private readonly IOptions<LumaOptions> _options;

        public AuthorizeService(
            IClientRepository clientRepository,
            IAuthorizationCodeStateProvider authorizationCodeStateProvider,
            IAuthorizationCodeProvider authorizationCodeProvider,
            IOptions<LumaOptions> options)
        {
            _clientRepository = clientRepository;
            _authorizationCodeStateProvider = authorizationCodeStateProvider;
            _authorizationCodeProvider = authorizationCodeProvider;
            _options = options;
        }
        
        public async Task<(bool redirectSafe, OAuthServiceResponse<string>)> CreateAuthorizationCodeStateAsync(AuthorizeRequestDTO request)
        {
            var state = request.state;
            if (string.IsNullOrEmpty(request.state))
                return (false, OAuthServiceResponse<string>.Failure("invalid_request", "The state parameter is required.", state));

            if (string.IsNullOrEmpty(request.client_id))
                return (false, OAuthServiceResponse<string>.Failure("invalid_request", "The client_id is required.", state));

            var client = _clientRepository.FindClientById(request.client_id);
            if (client == null)
                return (false, OAuthServiceResponse<string>.Failure("invalid_request", "The specified client_id is invalid.", state));

            var clientId = client.ClientId;
            var redirectUri = request.redirect_uri ?? client.DefaultRedirectUri;

            if (!_clientRepository.ClientHasRedirectUri(clientId, redirectUri))
                return (false, OAuthServiceResponse<string>.Failure("invalid_request", "The specified redirect_uri is not registered for the client.", state));

            if (!_clientRepository.ClientAllowsGrantType(clientId, "authorization_code"))
                return (true, OAuthServiceResponse<string>.Failure("unauthorized_client", "The client is not authorized to use the authorization_code grant type.", state));

            if (request.response_type != "code")
                return (true, OAuthServiceResponse<string>.Failure("unsupported_response_type", "The response_type is not supported.", state));

            if (!client.IsConfidential && (string.IsNullOrEmpty(request.code_challenge) || string.IsNullOrEmpty(request.code_challenge_method)))
                return (true, OAuthServiceResponse<string>.Failure("invalid_request", "Public clients must use PKCE (code_challenge and code_challenge_method are required).", state));

            var scope = request.scope ?? client.DefaultScope;

            if (!_clientRepository.ClientHasScope(clientId, scope.Split(' ')))
                return (true, OAuthServiceResponse<string>.Failure("invalid_scope", "The specified scope is not allowed for the client.", state));

            if (!string.IsNullOrEmpty(request.code_challenge_method) && string.IsNullOrEmpty(request.code_challenge))
            {
                return (true, OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge is required when code_challenge_method is specified.", state));
            }
            
            if (!string.IsNullOrEmpty(request.code_challenge))
            {
                if (string.IsNullOrEmpty(request.code_challenge_method))
                    return (true, OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge_method required.", state));
                if (!string.Equals(request.code_challenge_method, "S256", StringComparison.OrdinalIgnoreCase))
                    return (true, OAuthServiceResponse<string>.Failure("invalid_request", "Only S256 code_challenge_method is supported.", state));
            }

            var codeChallenge = request.code_challenge;
            var codeChallengeMethod = request.code_challenge_method;
            var nonce = request.nonce;

            if (request.response_mode != null &&
                request.response_mode != "query" &&
                request.response_mode != "form_post")
            {
                return (true, OAuthServiceResponse<string>.Failure("invalid_request", "The specified response_mode is not supported.", state));
            }

            var responseMode = request.response_mode;

            if (request.prompt != null && 
                request.prompt != "consent" &&
                request.prompt != "login" &&
                request.prompt != "none" &&
                request.prompt != "select_account")
            {
                return (true, OAuthServiceResponse<string>.Failure("invalid_request", "The specified prompt value is not supported.", state));
            }

            var prompt = request.prompt;

            if (request.max_age != null && request.max_age < 0)
            {
                return (true, OAuthServiceResponse<string>.Failure("invalid_request", "The max_age must be a non-negative integer.", state));
            }

            var maxAge = request.max_age;
            var loginHint = request.login_hint;
            var claims = request.claims;
            if (claims != null) {
                try
                {
                    var parsedClaims = System.Text.Json.JsonDocument.Parse(claims);
                }
                catch (System.Text.Json.JsonException)
                {
                    return (true, OAuthServiceResponse<string>.Failure("invalid_request", "The claims parameter is not a valid JSON object.", state));
                }
            }

            var codeState = new AuthorizationCodeStateDTO(
                    state: state,
                    clientId: clientId,
                    redirectUri: redirectUri,
                    scope: scope,
                    codeChallengeMethod: codeChallengeMethod,
                    codeChallenge: codeChallenge,
                    nonce: nonce,
                    responseMode: responseMode,
                    prompt: prompt,
                    maxAge: maxAge,
                    loginHint: loginHint,
                    claims: claims);

            var result = await _authorizationCodeStateProvider.SaveAsync(codeState.state, codeState);
            if (result == false)
                return (true, OAuthServiceResponse<string>.Failure("server_error", "Failed to store authorization code state.", state));

            return (true, OAuthServiceResponse<string>.Success(redirectUri, codeState.state));
        }

        public async Task<ServiceResponse<AuthorizationCodeStateDTO>> GetAuthorizationCodeStateAsync(string clientId, string state)
        {
            if (string.IsNullOrEmpty(state))
                return ServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The state parameter is required.");

            var result =  await _authorizationCodeStateProvider.GetAsync(state);
            if (result == null)
                return ServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The specified state does not exist.");

            if (result.clientId != clientId)
                return ServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The client_id does not match the stored authorization code state.");

            return ServiceResponse<AuthorizationCodeStateDTO>.Success(result);
        }

        public async Task<ServiceResponse<bool>> DeleteAuthorizationCodeStateAsync(string clientId, string state)
        {
            if (string.IsNullOrEmpty(state))
                return ServiceResponse<bool>.Failure("invalid_request", "The state parameter is required.");
            
            var existingStateResult = await _authorizationCodeStateProvider.GetAsync(state);
            if (existingStateResult == null)
                return ServiceResponse<bool>.Failure("invalid_request", "The specified state does not exist.");

            if (existingStateResult.clientId != clientId)
                return ServiceResponse<bool>.Failure("invalid_request", "The client_id does not match the stored authorization code state.");
            
            var deleteResult = await _authorizationCodeStateProvider.DeleteAsync(state);
            if (deleteResult == false)
                return ServiceResponse<bool>.Failure("server_error", "Failed to delete the authorization code state.");

            return ServiceResponse<bool>.Success(true);
        }

        public async Task<OAuthServiceResponse<string>> GenerateAuthorizationCodeAsync(string state)
        {
            var existingStateResult = await _authorizationCodeStateProvider.GetAsync(state);
            if (existingStateResult == null)
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified state does not exist.", state);

            var client = _clientRepository.FindClientById(existingStateResult.clientId);
            if (client == null)
                return OAuthServiceResponse<string>.Failure("invalid_request", "The client associated with the authorization code state does not exist.", state);

            if (!_clientRepository.ClientAllowsGrantType(existingStateResult.clientId, "authorization_code"))
                return OAuthServiceResponse<string>.Failure("unauthorized_client", "The client is not authorized to use the authorization_code grant type.", state);

            if (!_clientRepository.ClientHasRedirectUri(existingStateResult.clientId, existingStateResult.redirectUri ?? client.DefaultRedirectUri))
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified redirect_uri is not registered for the client.", state);

            if (!string.IsNullOrEmpty(existingStateResult.codeChallengeMethod) && string.IsNullOrEmpty(existingStateResult.codeChallenge))
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge is required when code_challenge_method is specified.", state);
            }

            if (!string.IsNullOrEmpty(existingStateResult.codeChallenge))
            {
                if (string.IsNullOrEmpty(existingStateResult.codeChallengeMethod))
                    return OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge_method required.", state);
                if (!string.Equals(existingStateResult.codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
                    return OAuthServiceResponse<string>.Failure("invalid_request", "Only S256 code_challenge_method is supported.", state);
            }

            var randomBytes = RandomNumberGenerator.GetBytes(32);
            var code = Base64UrlEncoder.Encode(randomBytes);
            var expiresIn = _options.Value.OAuth.AuthorizationCode.ValidForSeconds;
            if (expiresIn < 60 || expiresIn > 120)
                expiresIn = 90; // enforce default of 90 seconds if out of bounds

            var entry = new AuthorizationCode
            {
                Code = code,
                ClientId = existingStateResult.clientId,
                RedirectUri = existingStateResult.redirectUri ?? client.DefaultRedirectUri,
                CodeChallenge = existingStateResult.codeChallenge,
                CodeChallengeMethod = existingStateResult.codeChallengeMethod,
                Scope = existingStateResult.scope ?? client.DefaultScope,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
            };

            var codeCreated = await _authorizationCodeProvider.SaveAsync(code, entry, expiresIn);
            if (codeCreated == false)
                return OAuthServiceResponse<string>.Failure("server_error", "Failed to store authorization code.", state);

            if (string.IsNullOrEmpty(code))
                return OAuthServiceResponse<string>.Failure("server_error", "Failed to generate authorization code.", state);
            return OAuthServiceResponse<string>.Success(code, state);
        }

        public async Task<OAuthServiceResponse<bool>> ValidateAndUseAuthorizationCodeAsync(string code, string clientId)
        {
            var existingCode = await _authorizationCodeProvider.GetAsync(code);
            if (existingCode == null)
                return OAuthServiceResponse<bool>.Failure("invalid_grant", "The specified authorization code is invalid or has expired.", clientId);
            if (existingCode.ClientId != clientId)
                return OAuthServiceResponse<bool>.Failure("invalid_grant", "The client_id does not match the authorization code.", clientId);
            if (existingCode.Used)
                return OAuthServiceResponse<bool>.Failure("invalid_grant", "The authorization code has already been used.", clientId);
            existingCode.Used = true;
            var updateResult = await _authorizationCodeProvider.DeleteAsync(existingCode);
            if (updateResult == false)
                return OAuthServiceResponse<bool>.Failure("server_error", "Failed to mark authorization code as used.", clientId);
            return OAuthServiceResponse<bool>.Success(true, clientId);
        }
    }
}
