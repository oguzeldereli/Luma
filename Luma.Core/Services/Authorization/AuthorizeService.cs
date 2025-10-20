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
    public class AuthorizeService : IAuthorizeService
    {
        private readonly IClientRepository _clientRepository;
        private readonly IAuthorizationCodeStateProvider _authorizationCodeStateProvider;

        public AuthorizeService(
            IClientRepository clientRepository,
            IAuthorizationCodeStateProvider authorizationCodeStateProvider)
        {
            _clientRepository = clientRepository;
            _authorizationCodeStateProvider = authorizationCodeStateProvider;
        }
        
        public async Task<OAuthServiceResponse<AuthorizationCodeStateDTO>> StartAuthorizationAsync(AuthorizeRequestDTO request)
        {
            var state = request.state;
            if (string.IsNullOrEmpty(request.state))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The state parameter is required.", state);

            if (request.response_type != "code")
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The response_type is not supported.", state);

            if (string.IsNullOrEmpty(request.client_id))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The client_id is required.", state);

            var client = _clientRepository.FindClientById(request.client_id);
            if (client == null)
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The specified client_id is invalid.", state);

            var clientId = client.ClientId;
            var redirectUri = request.redirect_uri ?? client.DefaultRedirectUri;

            if (!_clientRepository.ClientAllowsGrantType(clientId, "authorization_code"))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("unauthorized_client", "The client is not authorized to use the authorization_code grant type.", state);

            if (!_clientRepository.ClientHasRedirectUri(clientId, redirectUri))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The specified redirect_uri is not registered for the client.", state);

            if (!client.IsConfidential && (string.IsNullOrEmpty(request.code_challenge) || string.IsNullOrEmpty(request.code_challenge_method)))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "Public clients must use PKCE (code_challenge and code_challenge_method are required).", state);

            var scope = request.scope ?? client.DefaultScope;

            if (!_clientRepository.ClientHasScope(clientId, scope.Split(' ')))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_scope", "The specified scope is not allowed for the client.", state);

            if (!string.IsNullOrEmpty(request.code_challenge_method) && string.IsNullOrEmpty(request.code_challenge))
            {
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "code_challenge is required when code_challenge_method is specified.", state);
            }
            
            if (!string.IsNullOrEmpty(request.code_challenge))
            {
                if (string.IsNullOrEmpty(request.code_challenge_method))
                    return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "code_challenge_method required.", state);
                if (!string.Equals(request.code_challenge_method, "S256", StringComparison.OrdinalIgnoreCase))
                    return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "Only S256 code_challenge_method is supported.", state);
            }

            var codeChallenge = request.code_challenge;
            var codeChallengeMethod = request.code_challenge_method;
            var nonce = request.nonce;

            if (request.response_mode != null &&
                request.response_mode != "query" &&
                request.response_mode != "form_post")
            {
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The specified response_mode is not supported.", state);
            }

            var responseMode = request.response_mode;

            if (request.prompt != null && 
                request.prompt != "consent" &&
                request.prompt != "login" &&
                request.prompt != "none" &&
                request.prompt != "select_account")
            {
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The specified prompt value is not supported.", state);
            }

            var prompt = request.prompt;

            if (request.max_age != null && request.max_age < 0)
            {
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The max_age must be a non-negative integer.", state);
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
                    return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The claims parameter is not a valid JSON object.", state);
                }
            }

            return OAuthServiceResponse<AuthorizationCodeStateDTO>.Success(
                new AuthorizationCodeStateDTO(
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
                    claims: claims), state);
        }

        public async Task<OAuthServiceResponse<(string clientId, string state)>> SaveAuthorizationCodeStateAsync(AuthorizationCodeStateDTO codeState)
        {            
            if (codeState == null)
                return OAuthServiceResponse<(string clientId, string state)>.Failure("invalid_request", "The code state cannot be null.", "");

            if (string.IsNullOrEmpty(codeState.state))
                return OAuthServiceResponse<(string clientId, string state)>.Failure("invalid_request", "The state parameter is required.", "");

            var result = await _authorizationCodeStateProvider.SaveAsync(codeState.state, codeState);
            if (result.Data == false)
                return OAuthServiceResponse<(string clientId, string state)>.Failure(result.ErrorCode, result.ErrorMessage, result.State);

            return OAuthServiceResponse<(string clientId, string state)>.Success((codeState.clientId, codeState.state), codeState.state);
        }

        public async Task<OAuthServiceResponse<AuthorizationCodeStateDTO>> GetAuthorizationCodeStateAsync(string clientId, string state)
        {
            if (string.IsNullOrEmpty(state))
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The state parameter is required.", state);

            var result =  await _authorizationCodeStateProvider.GetAsync(state);
            if (result.Data == null)
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure(result.ErrorCode, result.ErrorMessage, result.State);

            if (result.Data.clientId != clientId)
                return OAuthServiceResponse<AuthorizationCodeStateDTO>.Failure("invalid_request", "The client_id does not match the stored authorization code state.", state);

            return OAuthServiceResponse<AuthorizationCodeStateDTO>.Success(result.Data, state);
        }

        public async Task<OAuthServiceResponse<bool>> DeleteAuthorizationCodeStateAsync(string clientId, string state)
        {
            if (string.IsNullOrEmpty(state))
                return OAuthServiceResponse<bool>.Failure("invalid_request", "The state parameter is required.", state);
            
            var existingStateResult = await _authorizationCodeStateProvider.GetAsync(state);
            if (existingStateResult.Data == null)
                return OAuthServiceResponse<bool>.Failure(existingStateResult.ErrorCode, existingStateResult.ErrorMessage, existingStateResult.State);
            
            if (existingStateResult.Data.clientId != clientId)
                return OAuthServiceResponse<bool>.Failure("invalid_request", "The client_id does not match the stored authorization code state.", state);
            
            var deleteResult = await _authorizationCodeStateProvider.DeleteAsync(state);
            if (deleteResult.Data == false)
                return OAuthServiceResponse<bool>.Failure(deleteResult.ErrorCode, deleteResult.ErrorMessage, deleteResult.State);
            
            return OAuthServiceResponse<bool>.Success(true, state);
        }

        public async Task<OAuthServiceResponse<string>> GenerateAuthorizationCodeAsync(AuthorizationCodeStateDTO codeState)
        {
            throw new NotImplementedException();
        }

        public async Task<OAuthServiceResponse<bool>> ValidateAuthorizationCodeAsync(string code, string clientId)
        {
            throw new NotImplementedException();
        }
    }
}
