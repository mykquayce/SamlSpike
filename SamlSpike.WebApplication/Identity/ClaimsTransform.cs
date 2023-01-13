using ITfoxtec.Identity.Saml2.Claims;
using System.Security.Claims;

namespace SamlSpike.WebApplication.Identity;

public static class ClaimsTransform
{
	public static ClaimsPrincipal Transform(ClaimsPrincipal incomingPrincipal)
	{
		if (incomingPrincipal.Identity?.IsAuthenticated != true)
		{
			return incomingPrincipal;
		}

		return CreateClaimsPrincipal(incomingPrincipal);
	}

	private static ClaimsPrincipal CreateClaimsPrincipal(ClaimsPrincipal incomingPrincipal)
	{
		var claims = new List<Claim>();

		// All claims
		claims.AddRange(incomingPrincipal.Claims);

		// Or custom claims
		//claims.AddRange(GetSaml2LogoutClaims(incomingPrincipal));
		//claims.Add(new Claim(ClaimTypes.NameIdentifier, GetClaimValue(incomingPrincipal, ClaimTypes.NameIdentifier)));

		var identity = new ClaimsIdentity(claims, incomingPrincipal.Identity?.AuthenticationType, ClaimTypes.NameIdentifier, ClaimTypes.Role)
		{
			BootstrapContext = (incomingPrincipal.Identity as ClaimsIdentity)?.BootstrapContext,
		};

		return new ClaimsPrincipal(identity);
	}

	private static IEnumerable<Claim?> GetSaml2LogoutClaims(ClaimsPrincipal principal)
	{
		yield return f(Saml2ClaimTypes.NameId);
		yield return f(Saml2ClaimTypes.NameIdFormat);
		yield return f(Saml2ClaimTypes.SessionIndex);

		Claim? f(string claimType) => GetClaim(principal, claimType);
	}

	private static Claim? GetClaim(ClaimsPrincipal principal, string claimType)
	{
		return (principal.Identity as ClaimsIdentity)?.Claims.FirstOrDefault(x => x.Type == claimType);
	}

	private static string? GetClaimValue(ClaimsPrincipal principal, string claimType)
	{
		var claim = GetClaim(principal, claimType);
		return claim?.Value;
	}
}
