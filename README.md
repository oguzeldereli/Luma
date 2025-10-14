# Luma

Luma Auth is a lightweight, modern, and self-hostable authentication and token management server built.
It’s designed as a plug-and-play alternative to heavier solutions like Auth0, Keycloak, or Duende IdentityServer, with simplicity, transparency, and developer control in mind.

Luma Auth handles everything from magic link logins and numeric code verification to OAuth2 token issuance, while keeping configuration effortless through a single luma.config.json file or environment variables. It only allows **passwordless** authentication methods.

It’s built entirely on Entity Framework Core, ASP.NET Core, and HMAC-secured tokens, with full flexibility to run on SQLite, PostgreSQL, or SQL Server, locally or in production.

## License

**Luma Auth** is licensed under the **Elastic License 2.0**.

You may:

-   Use, copy, modify, and distribute Luma Auth for free, including in commercial projects.
-   Self-host it privately or within your own infrastructure.

You may not:

-   Offer Luma Auth itself as a **hosted or managed service** (e.g., “LumaAuth Cloud”).
-   Remove license notices or trademarks.

See the [LICENSE](./LICENSE) file for full terms.
