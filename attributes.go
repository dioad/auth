package auth

// Canonical attribute key constants for PrincipalContext.Attributes.
//
// These names normalise cross-provider identity fields so that
// application code and ClaimRoleMapper rules can reference common
// fields without knowing which IdP issued the token.
//
// Provider-specific claims (e.g. "repository", "app_name") are also
// present in Attributes under their raw JWT claim names.
const (
	// AttrEmail is the primary/verified email address.
	AttrEmail = "primary_email"

	// AttrEmailVerified indicates whether the email address has been verified.
	AttrEmailVerified = "primary_email_verified"

	// AttrUsername is the login name or username for the principal.
	AttrUsername = "username"

	// AttrPreferredUsername is the display name or preferred username.
	AttrPreferredUsername = "preferred_username"

	// AttrUserPrincipalName is the user principal name (UPN), used by Azure AD.
	AttrUserPrincipalName = "user_principal_name"

	// AttrOrganisation is the organisation or tenant name associated with the principal.
	AttrOrganisation = "organisation"
)
