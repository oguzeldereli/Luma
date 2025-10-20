using Luma.Core.Models.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace Luma.Core.Interfaces.Authorization
{
    public interface IClientRepository
    {
        // TODO: RegisterClient();
        List<Client> GetAllClients();
        Client? FindClientById(string clientId);
        bool ClientExists(string clientId);
        bool ClientHasRedirectUri(string clientId, string redirectUri);
        bool ClientAllowsGrantType(string clientId, string grantType);
        bool ClientHasScope(string clientId, params string[] scopes);
        bool ClientIsConfidential(string clientId);
        bool AuthenticateClient(string clientId, string clientSecret);
    }
}
