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
        
        public async Task<OAuthServiceResponse<string>> CreateAuthorizationCodeStateAsync(AuthorizeRequestDTO request)
        {
            if (string.IsNullOrWhiteSpace(request.state))
                return OAuthServiceResponse<string>.Failure("invalid_request", "The state parameter is required.", 400, null, request.state, null, request.response_mode ?? "query");

            var state = request.state;

            if (string.IsNullOrWhiteSpace(request.client_id))
                return OAuthServiceResponse<string>.Failure("invalid_request", "The client_id is required.", 400, null, state, null, request.response_mode ?? "query");

            var client = _clientRepository.FindClientById(request.client_id);
            if (client == null)
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified client_id is invalid.", 400, null, state, null, request.response_mode ?? "query");

            var clientId = client.ClientId;
            var redirectUri = request.redirect_uri ?? client.DefaultRedirectUri;

            if (string.IsNullOrWhiteSpace(redirectUri) || !_clientRepository.ClientHasRedirectUri(clientId, redirectUri))
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified redirect_uri is not registered for the client.", 400, null, state, null, request.response_mode ?? "query");

            var resource = request.resource ?? client.DefaultResource;

            if (string.IsNullOrWhiteSpace(resource) || !_clientRepository.ClientHasResource(clientId, resource))
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified resource is not allowed for the client.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");

            if (!_clientRepository.ClientAllowsGrantType(clientId, "authorization_code"))
                return OAuthServiceResponse<string>.Failure("unauthorized_client", "The client is not authorized to use the authorization_code grant type.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");

            if (request.response_type != "code")
                return OAuthServiceResponse<string>.Failure("unsupported_response_type", "The response_type is not supported.", 302, null, state, request.redirect_uri);

            if (!client.IsConfidential && (string.IsNullOrEmpty(request.code_challenge) || string.IsNullOrEmpty(request.code_challenge_method)))
                return OAuthServiceResponse<string>.Failure("invalid_request", "Public clients must use PKCE (code_challenge and code_challenge_method are required).", 302, null, state, request.redirect_uri, request.response_mode ?? "query");

            var scope = request.scope ?? client.DefaultScope;

            if (string.IsNullOrWhiteSpace(scope) || !_clientRepository.ClientHasScope(clientId, scope.Split(' ')))
                return OAuthServiceResponse<string>.Failure("invalid_scope", "The specified scope is not allowed for the client.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");

            if (!string.IsNullOrWhiteSpace(request.code_challenge_method) && string.IsNullOrWhiteSpace(request.code_challenge))
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge is required when code_challenge_method is specified.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
            }
            
            if (!string.IsNullOrWhiteSpace(request.code_challenge))
            {
                if (string.IsNullOrWhiteSpace(request.code_challenge_method))
                    return OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge_method required.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
                if (!string.Equals(request.code_challenge_method, "S256", StringComparison.OrdinalIgnoreCase))
                    return OAuthServiceResponse<string>.Failure("invalid_request", "Only S256 code_challenge_method is supported.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
            }

            var codeChallenge = request.code_challenge;
            var codeChallengeMethod = request.code_challenge_method;
            var nonce = request.nonce;

            if (request.response_mode != null &&
                request.response_mode != "query" &&
                request.response_mode != "form_post")
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified response_mode is not supported.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
            }

            var responseMode = request.response_mode;

            if (request.prompt != null && 
                request.prompt != "consent" &&
                request.prompt != "login" &&
                request.prompt != "none" &&
                request.prompt != "select_account")
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified prompt value is not supported.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
            }

            var prompt = request.prompt;

            if (request.max_age != null && request.max_age < 0)
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "The max_age must be a non-negative integer.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
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
                    return OAuthServiceResponse<string>.Failure("invalid_request", "The claims parameter is not a valid JSON object.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");
                }
            }

            var newId = Guid.NewGuid().ToString();
            var codeState = new AuthorizationCodeStateDTO(
                    id: newId,
                    state: state,
                    clientId: clientId,
                    redirectUri: redirectUri,
                    resource: resource,
                    scope: scope,
                    codeChallengeMethod: codeChallengeMethod,
                    codeChallenge: codeChallenge,
                    nonce: nonce,
                    responseMode: responseMode,
                    prompt: prompt,
                    maxAge: maxAge,
                    loginHint: loginHint,
                    claims: claims);

            var result = await _authorizationCodeStateProvider.SaveAsync(newId, codeState);
            if (result == false)
                return OAuthServiceResponse<string>.Failure("server_error", "Failed to store authorization code state.", 302, null, state, request.redirect_uri, request.response_mode ?? "query");

            return OAuthServiceResponse<string>.Success(newId, 302, codeState.state, redirectUri, request.response_mode ?? "query");
        }

        public async Task<OAuthServiceResponse<(string clientId, string requestUri)>> CreateParAsync(ParRequestDTO request)
        {
            var authorizeRequest = new AuthorizeRequestDTO
            (
                response_type: request.response_type,
                client_id: request.client_id,
                redirect_uri: request.redirect_uri,
                scope: request.scope,
                state: request.state ?? Guid.NewGuid().ToString(),
                resource: request.resource,
                code_challenge: request.code_challenge,
                code_challenge_method: request.code_challenge_method,
                nonce: request.nonce,
                response_mode: request.response_mode,
                prompt: request.prompt,
                max_age: request.max_age,
                login_hint: request.login_hint,
                claims: request.claims
            );

            if (string.IsNullOrWhiteSpace(request.client_id) || !_clientRepository.ClientExists(request.client_id))
            {
                return OAuthServiceResponse<(string clientId, string requestUri)>.Failure(
                    "invalid_client",
                    "The client_id provided is invalid.",
                    401, null, null, null, null);
            }

            if (_clientRepository.ClientIsConfidential(request.client_id) && (request.client_secret == null || !_clientRepository.AuthenticateClient(request.client_id, request.client_secret)))
            {
                return OAuthServiceResponse<(string clientId, string requestUri)>.Failure(
                    "invalid_client",
                    "The client authentication failed.",
                    401, null, null, null, null);
            }

            var client = _clientRepository.FindClientById(request.client_id);

            var result = await CreateAuthorizationCodeStateAsync(authorizeRequest);
            if (result.ErrorCode != null || result.Data == null)
            {
                return OAuthServiceResponse<(string clientId, string requestUri)>.Failure(
                    result.ErrorCode ?? "server_error",
                    result.ErrorMessage ?? "Couldn't create authorization state. An unexpected error occured.",
                    result.StatusCode ?? 500,
                    result.ErrorUri,
                    result.State ?? request.state,
                    result.RedirectUri);
            }

            if (result.Data == null)
            {
                return OAuthServiceResponse<(string clientId, string requestUri)>.Failure(
                    "server_error",
                    "Failed to store PAR state.",
                    500,
                    null,
                    result.State,
                    result.RedirectUri);
            }

            return OAuthServiceResponse<(string clientId, string requestUri)>.Success(
                (request.client_id, "urn:ietf:params:oauth:request_uri:" + result.Data),
                200,
                result.State,
                result.RedirectUri,
                result.ResponseMode);
        }

        public async Task<OAuthServiceResponse<string>> GetParStateAsync(string requestUri)
        {
            var prefix = "urn:ietf:params:oauth:request_uri:";
            if (!requestUri.StartsWith(prefix, StringComparison.Ordinal))
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "Invalid request_uri format", 400);
            }

            string id = requestUri.Substring(prefix.Length);

            return OAuthServiceResponse<string>.Success(id);
        }

        public async Task<ServiceResponse<AuthorizationCodeStateDTO>> GetAuthorizationCodeStateAsync(string clientId, string stateId)
        {
            if (string.IsNullOrWhiteSpace(stateId))
                return ServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The state parameter is required.");

            var result =  await _authorizationCodeStateProvider.GetAsync(stateId);
            if (result == null)
                return ServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The specified state does not exist.");

            if (result.clientId != clientId)
                return ServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The client_id does not match the stored authorization code state.");

            return ServiceResponse<AuthorizationCodeStateDTO>.Success(result);
        }

        public async Task<ServiceResponse<bool>> DeleteAuthorizationCodeStateAsync(string clientId, string stateId)
        {
            if (string.IsNullOrWhiteSpace(stateId))
                return ServiceResponse<bool>.Failure("invalid_request", "The state parameter is required.");
            
            var existingStateResult = await _authorizationCodeStateProvider.GetAsync(stateId);
            if (existingStateResult == null)
                return ServiceResponse<bool>.Failure("invalid_request", "The specified state does not exist.");

            if (existingStateResult.clientId != clientId)
                return ServiceResponse<bool>.Failure("invalid_request", "The client_id does not match the stored authorization code state.");
            
            var deleteResult = await _authorizationCodeStateProvider.DeleteAsync(stateId);
            if (deleteResult == false)
                return ServiceResponse<bool>.Failure("server_error", "Failed to delete the authorization code state.");

            return ServiceResponse<bool>.Success(true);
        }

        public async Task<OAuthServiceResponse<string>> GenerateAuthorizationCodeAsync(long userId, string stateId)
        {
            var existingStateResult = await _authorizationCodeStateProvider.GetAsync(stateId);
            if (existingStateResult == null)
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified state id does not exist.", 400, null, null, null, null);

            var state = existingStateResult.state;
            var redirectUri = existingStateResult.redirectUri;
            var responseMode = existingStateResult.responseMode;

            var client = _clientRepository.FindClientById(existingStateResult.clientId);
            if (client == null)
                return OAuthServiceResponse<string>.Failure("invalid_request", "The client associated with the authorization code state does not exist.", 302, null, state, redirectUri, responseMode);

            if (!_clientRepository.ClientAllowsGrantType(existingStateResult.clientId, "authorization_code"))
                return OAuthServiceResponse<string>.Failure("unauthorized_client", "The client is not authorized to use the authorization_code grant type.", 302, null, state, redirectUri, responseMode);

            if (!_clientRepository.ClientHasRedirectUri(existingStateResult.clientId, existingStateResult.redirectUri ?? client.DefaultRedirectUri))
                return OAuthServiceResponse<string>.Failure("invalid_request", "The specified redirect_uri is not registered for the client.", 302, null, state, redirectUri, responseMode);

            if (!string.IsNullOrWhiteSpace(existingStateResult.codeChallengeMethod) && string.IsNullOrWhiteSpace(existingStateResult.codeChallenge))
            {
                return OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge is required when code_challenge_method is specified.", 302, null, state, redirectUri, responseMode);
            }

            if (!string.IsNullOrWhiteSpace(existingStateResult.codeChallenge))
            {
                if (string.IsNullOrWhiteSpace(existingStateResult.codeChallengeMethod))
                    return OAuthServiceResponse<string>.Failure("invalid_request", "code_challenge_method required.", 302, null, state, redirectUri, responseMode);
                if (!string.Equals(existingStateResult.codeChallengeMethod, "S256", StringComparison.OrdinalIgnoreCase))
                    return OAuthServiceResponse<string>.Failure("invalid_request", "Only S256 code_challenge_method is supported.", 302, null, state, redirectUri, responseMode);
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
                Resource = existingStateResult.resource ?? client.DefaultResource,
                RedirectUri = existingStateResult.redirectUri ?? client.DefaultRedirectUri,
                CodeChallenge = existingStateResult.codeChallenge,
                CodeChallengeMethod = existingStateResult.codeChallengeMethod,
                Scope = existingStateResult.scope ?? client.DefaultScope,
                Nonce = existingStateResult.nonce,
                UserId = userId,
                CreatedAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddSeconds(expiresIn)
            };

            var codeCreated = await _authorizationCodeProvider.SaveAsync(code, entry, expiresIn);
            if (codeCreated == false)
                return OAuthServiceResponse<string>.Failure("server_error", "Failed to store authorization code.", 302, null, state, redirectUri, responseMode);

            var deleteStateResult = await _authorizationCodeStateProvider.DeleteAsync(stateId);
            if (deleteStateResult == false)
                return OAuthServiceResponse<string>.Failure("server_error", "Failed to delete authorization code state after generating code.", 302, null, state, redirectUri, responseMode);

            if (string.IsNullOrWhiteSpace(code))
                return OAuthServiceResponse<string>.Failure("server_error", "Failed to generate authorization code.", 302, null, state, redirectUri, responseMode);
            return OAuthServiceResponse<string>.Success(code, 302, state, redirectUri, responseMode);
        }

        public async Task<OAuthServiceResponse<AuthorizationCode>> ValidateAndUseAuthorizationCodeAsync(string code, string clientId)
        {
            var existingCode = await _authorizationCodeProvider.GetAsync(code);
            if (existingCode == null)
                return OAuthServiceResponse<AuthorizationCode>.Failure("invalid_grant", "The specified authorization code is invalid or has expired.", 400, null, null, null, null);
            if (existingCode.ClientId != clientId)
                return OAuthServiceResponse<AuthorizationCode>.Failure("invalid_grant", "The client_id does not match the authorization code.", 400, null, null, null, null);
            if (existingCode.Used)
                return OAuthServiceResponse<AuthorizationCode>.Failure("invalid_grant", "The authorization code has already been used.", 400, null, null, null, null);
            var deleteResults = await _authorizationCodeProvider.DeleteAsync(code);
            if (deleteResults == false)
                return OAuthServiceResponse<AuthorizationCode>.Failure("server_error", "Failed to mark authorization code as used.", 400, null, null, null, null);
            return OAuthServiceResponse<AuthorizationCode>.Success(existingCode);
        }

        public async Task<bool> VerifyPkceCodeVerifierAsync(string codeVerifier, string codeChallenge, string codeChallengeMethod)
        {
            if (codeChallengeMethod != "S256")
                return false;
            using var sha256 = SHA256.Create();
            var verifierBytes = Encoding.ASCII.GetBytes(codeVerifier);
            var hashBytes = sha256.ComputeHash(verifierBytes);
            var computedChallenge = Base64UrlEncoder.Encode(hashBytes);
            return string.Equals(computedChallenge, codeChallenge, StringComparison.Ordinal);
        }
    }
}
