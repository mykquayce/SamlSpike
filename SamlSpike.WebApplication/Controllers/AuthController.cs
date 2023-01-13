using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SamlSpike.WebApplication.Identity;
using System.Security.Authentication;

namespace SamlSpike.WebApplication.Controllers;

[AllowAnonymous]
[Route("Auth")]
public class AuthController : Controller
{
	private const string _relayStateReturnUrl = "ReturnUrl";
	private readonly Saml2Configuration _config;

	public AuthController(IOptions<Saml2Configuration> configAccessor)
	{
		_config = configAccessor.Value;
	}

	[Route("Login")]
	public IActionResult Login(string? returnUrl = null)
	{
		var request = new Saml2AuthnRequest(_config);

		var elements = new Dictionary<string, string>
		{
			[_relayStateReturnUrl] = returnUrl ?? Url.Content("~/"),
		};

		var binding = new Saml2RedirectBinding();
		binding.SetRelayStateQuery(elements);
		return binding.Bind(request).ToActionResult();
	}

	[Route("AssertionConsumerService")]
	public async Task<IActionResult> AssertionConsumerService()
	{
		var binding = new Saml2PostBinding();
		var saml2AuthnResponse = new Saml2AuthnResponse(_config);

		binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
		if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
		{
			throw new AuthenticationException($"SAML Response status: {saml2AuthnResponse.Status}");
		}
		binding.Unbind(Request.ToGenericHttpRequest(), saml2AuthnResponse);
		await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: ClaimsTransform.Transform);

		var relayStateQuery = binding.GetRelayStateQuery();
		string returnUrl = relayStateQuery.TryGetValue(_relayStateReturnUrl, out string? value) ? value : Url.Content("~/");
		return Redirect(returnUrl);
	}

	[HttpPost("Logout")]
	[ValidateAntiForgeryToken]
	public async Task<IActionResult> Logout()
	{
		if (User.Identity?.IsAuthenticated != true)
		{
			return Redirect(Url.Content("~/"));
		}

		var binding = new Saml2PostBinding();
		var saml2LogoutRequest = await new Saml2LogoutRequest(_config, User).DeleteSession(HttpContext);
		return Redirect("~/");
	}
}
