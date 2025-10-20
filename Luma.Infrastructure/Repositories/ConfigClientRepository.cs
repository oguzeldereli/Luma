using Luma.Core.Interfaces.Authorization;
using Luma.Core.Models.Auth;
using Luma.Core.Options;
using Luma.Infrastructure.Security;
using Luma.Infrastructure.Utility;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Infrastructure.Repositories
{
    public class ConfigClientRepository : IClientRepository
    {
        private readonly IOptions<LumaOptions> _options;
        private List<Client> _clients;

        public ConfigClientRepository(
            IOptions<LumaOptions> options)
        {
            _options = options;
            _clients = _options.Value.OAuth.Clients?.Select(c => new Client
            {
                ClientId = c.ClientId,
                ClientSecretSHA256_Base64 = c.ClientSecretSHA256_Base64,
                DisplayName = c.DisplayName,
                DefaultRedirectUri = c.DefaultRedirectUri,
                RedirectUris = c.RedirectUris ?? new List<string>(),
                AllowedGrantTypes = c.AllowedGrantTypes ?? new List<string>(),
                DefaultScope = c.DefaultScope ?? "openid profile email",
                AllowedScopes = c.AllowedScopes ?? new List<string>(),
                IsConfidential = c.IsConfidential
            }).ToList() ?? new List<Client>();
        }

        public bool AuthenticateClient(string clientId, string clientSecret)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
                return false;
            var hash = Hasher.StringSHA256_Base64(clientSecret);
            return client.ClientSecretSHA256_Base64 == hash;
        }

        public bool ClientAllowsGrantType(string clientId, string grantType)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
                return false;
            return client.AllowedGrantTypes.Contains(grantType);
        }

        public bool ClientExists(string clientId)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            return client != null;
        }

        public bool ClientHasRedirectUri(string clientId, string redirectUri)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
                return false;
            return client.RedirectUris.Contains(redirectUri);
        }

        public bool ClientHasScope(string clientId, params string[] scopes)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
                return false;
            return scopes.All(s => client.AllowedScopes.Contains(s));
        }

        public bool ClientIsConfidential(string clientId)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            if (client == null)
                return false;
            return client.IsConfidential;
        }

        public Client? FindClientById(string clientId)
        {
            var client = _clients.FirstOrDefault(c => c.ClientId == clientId);
            return client!;
        }

        public List<Client> GetAllClients()
        {
            return _clients;
        }
    }
}
