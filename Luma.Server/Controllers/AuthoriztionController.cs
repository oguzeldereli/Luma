﻿using Luma.Core.DTOs.Authorization;
using Luma.Core.Interfaces.Authentication;
using Luma.Core.Interfaces.Services;
using Luma.Server.Utility;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;

namespace Luma.Controllers
{
    [Route("/")]
    public class AuthoriztionController : Controller
    {
        private readonly IAuthorizeService _authorizeService;
        private readonly ITokenService _tokenService;
        private readonly IUserLoginSessionCookieAccessor _userLoginSessionCookieAccessor;
        private readonly IUserLoginSessionProvider _userLoginSessionProvider;

        public AuthoriztionController(
            IAuthorizeService authorizeService,
            ITokenService tokenService,
            IUserLoginSessionCookieAccessor userLoginSessionCookieAccessor,
            IUserLoginSessionProvider userLoginSessionProvider
            )
        {
            _authorizeService = authorizeService;
            _tokenService = tokenService;
            _userLoginSessionCookieAccessor = userLoginSessionCookieAccessor;
            _userLoginSessionProvider = userLoginSessionProvider;
        }

        [HttpGet]
        [Route("authorize")]
        public async Task<IActionResult> StartAuthorizationFlowAsync([FromQuery] AuthorizeRequestDTO authorizeArgs)
        {
            var result = await _authorizeService.CreateAuthorizationCodeStateAsync(authorizeArgs);
            if (!string.IsNullOrWhiteSpace(result.ErrorCode) || result.Data == null)
            {
                return result.ToErrorResponse();
            }

            var token = _userLoginSessionCookieAccessor.GetLoginSessionToken();
            if (string.IsNullOrWhiteSpace(token))
            {
                return Redirect($"/login?state={result.State}");
            }

            var loginSession = await _userLoginSessionProvider.GetBySessionTokenAsync(token);
            if (loginSession == null)
            {
                return Redirect($"/login?state={result.State}");
            }

            var refreshedActivity = await _userLoginSessionProvider.RefreshActivityAsync(loginSession.Id);
            if (!refreshedActivity)
            {
                return Redirect($"/login?state={result.State}");
            }

            var prompts = (authorizeArgs.prompt ?? "")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (prompts.Contains("login"))
            {
                await _userLoginSessionProvider.RevokeAsync(loginSession.Id, "Prompt=login requested");
                _userLoginSessionCookieAccessor.ClearLoginSessionToken();

                return Redirect($"/login?state={result.State}");
            }
            else if (prompts.Contains("consent"))
            {
                return Redirect($"/consent?state={result.State}");
            }
            else if (prompts.Contains("select_account"))
            {
                return Redirect($"/select-account?state={result.State}");
            }

            var auth = await _authorizeService.GenerateAuthorizationCodeAsync(loginSession.UserId, result.State!);
            if (!string.IsNullOrWhiteSpace(auth.ErrorCode))
            {
                return auth.ToErrorResponse();
            }

            if (authorizeArgs.response_mode == "form_post")
            {
                return new ContentResult
                {
                    ContentType = "text/html",
                    Content = $"<html><body onload=\"document.forms[0].submit()\">" +
                                  $"<form method='post' action='{authorizeArgs.redirect_uri}'>" +
                                  $"<input type='hidden' name='code' value='{auth.Data}' />" +
                                  $"<input type='hidden' name='state' value='{auth.State}' />" +
                              "</form></body></html>"
                };
            }
            else
            {
                var queryParams = new Dictionary<string, string?>
                {
                    { "code", auth.Data },
                    { "state", auth.State }
                };
                var redirectUrl = QueryHelpers.AddQueryString(authorizeArgs.redirect_uri!, queryParams);
                return Redirect(redirectUrl);
            }
        }

        [HttpPost]
        [Route("token")]
        public async Task<IActionResult> Token([FromForm] TokenEndpointDTO request)
        {
            var clientId = HttpContext.Items["ClientId"] ?? request.client_id;
            var clientSecret = HttpContext.Items["ClientSecret"] ?? request.client_secret ?? "";
            if (clientId == null)
            {
                return BadRequest(new
                {
                    error = "invalid_client",
                    error_description = "Incomplete authentication data.",
                });
            }

            if (request.grant_type == "authorization_code")
            {
                TokenRequestDTO tokenRequestDTO = new TokenRequestDTO(
                    grant_type: request.grant_type,
                    code: request.code!,
                    redirect_uri: request.redirect_uri!,
                    client_id: clientId.ToString()!,
                    client_secret: clientSecret.ToString()!,
                    code_verifier: request.code_verifier,
                    resource: request.resource,
                    scope: request.scope
                    );

                var response = await _tokenService.IssueTokensFromAuthorizationCode(tokenRequestDTO);
                if (!string.IsNullOrWhiteSpace(response.ErrorCode) || response.Data == null)
                {
                    if (response.StatusCode == 401)
                    {
                        Response.Headers["WWW-Authenticate"] = "Basic";
                    }

                    return response.ToErrorResponse();
                }
                else
                {
                    return Ok(response.Data);
                }
            }
            else if (request.grant_type == "refresh_token")
            {
                TokenRefreshDTO tokenRefreshDTO = new TokenRefreshDTO(
                    grant_type: request.grant_type,
                    refresh_token: request.refresh_token!,
                    client_id: clientId.ToString()!,
                    client_secret: clientSecret.ToString()!,
                    resource: request.resource,
                    scope: request.scope
                    );
                var response = await _tokenService.IssueTokensFromRefreshToken(tokenRefreshDTO);
                if (!string.IsNullOrWhiteSpace(response.ErrorCode) || response.Data == null)
                {
                    if (response.StatusCode == 401)
                    {
                        Response.Headers["WWW-Authenticate"] = "Basic";
                    }

                    return response.ToErrorResponse();
                }
                else
                {
                    return Ok(response.Data);
                }
            }
            else if (request.grant_type == "client_credentials")
            {
                TokenClientCredentialsDTO tokenClientCredentialsDTO = new TokenClientCredentialsDTO(
                    grant_type: request.grant_type,
                    client_id: clientId.ToString()!,
                    client_secret: clientSecret.ToString()!,
                    resource: request.resource!,
                    scope: request.scope
                    );
                var response = await _tokenService.IssueTokensFromClientCredentials(tokenClientCredentialsDTO);
                if (!string.IsNullOrWhiteSpace(response.ErrorCode) || response.Data == null)
                {
                    if (response.StatusCode == 401)
                    {
                        Response.Headers["WWW-Authenticate"] = "Basic";
                    }
                    return response.ToErrorResponse();
                }
                else
                {
                    return Ok(response.Data);
                }
            }
            else
            {
                return BadRequest(new
                {
                    error = "unsupported_grant_type",
                    error_description = "The specified grant_type is not supported."
                });
            }
        }

        [Route("introspect")]
        public async Task<IActionResult> IntrospectToken([FromForm] TokenIntrospectionEndpointDTO request)
        {
            var clientId = HttpContext.Items["ClientId"] ?? request.client_id;
            var clientSecret = HttpContext.Items["ClientSecret"] ?? request.client_secret;
            if (clientId == null || clientSecret == null)
            {
                return BadRequest(new
                {
                    error = "invalid_client",
                    error_description = "Incomplete authentication data."
                });
            }

            TokenIntrospectionRequestDTO introspectionRequestDTO = new TokenIntrospectionRequestDTO(
                token: request.token,
                client_id: clientId.ToString()!,
                client_secret: clientSecret.ToString()!,
                token_type_hint: request.token_type_hint
                );

            var result = await _tokenService.IntrospectToken(introspectionRequestDTO);
            if (result.ErrorCode != null || result.Data == null)
            {
                return result.ToErrorResponse();
            }

            return Ok(result.Data);
        }

        [Route("revoke")]
        public async Task<IActionResult> RevokeToken([FromForm] TokenRevocationEndpointDTO request)
        {
            var clientId = HttpContext.Items["ClientId"] ?? request.client_id;
            var clientSecret = HttpContext.Items["ClientSecret"] ?? request.client_secret;
            if (clientId == null || clientSecret == null)
            {
                return BadRequest(new
                {
                    error = "invalid_client",
                    error_description = "Incomplete authentication data."
                });
            }

            TokenRevocationRequestDTO tokenRevocationRequestDTO = new TokenRevocationRequestDTO(
                token: request.token,
                client_id: clientId.ToString()!,
                client_secret: clientSecret.ToString()!,
                token_type_hint: request.token_type_hint
                );

            var result = await _tokenService.RevokeToken(tokenRevocationRequestDTO);
            if (result.ErrorCode != null)
            {
                return result.ToErrorResponse();
            }

            return Ok(result.Data);
        }

        [HttpGet]
        [HttpPost]
        [Route("userinfo")]
        public async Task<IActionResult> UserInfo()
        {
            var bearerToken = HttpContext.Items["BearerToken"]?.ToString();
            if (string.IsNullOrWhiteSpace(bearerToken))
            {
                Response.Headers["WWW-Authenticate"] = "Bearer realm=\"Luma\", error=\"invalid_token\", error_description=\"The access token is missing or invalid.\"";
                return Unauthorized(new
                {
                    error = "invalid_token",
                    error_description = "The access token is missing or invalid."
                });
            }

            var userInfo = await _tokenService.GetUserInfoAsync(bearerToken);
            if (userInfo.Data == null)
            {
                Response.Headers["WWW-Authenticate"] = "Bearer realm=\"Luma\", error=\"invalid_token\", error_description=\"The access token is missing or invalid.\"";
                return Unauthorized(new
                {
                    error = "invalid_token",
                    error_description = "The access token is missing or invalid."
                });
            }

            return Ok(userInfo.Data);
        }

        [Route(".well-known/openid-configuration")]
        public IActionResult OpenIDProviderMetadata()
        {
            return Ok();
        }

        [Route(".well-known/oauth-authorization-server")]
        public IActionResult OAuthAuthorizationServerMetadata()
        {
            return Ok();
        }
    }
}
