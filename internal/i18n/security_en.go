package i18n

// Admin-enforced 2FA and password reset links.
var enSecurity = map[string]string{
	"members.2fa_required":       "2FA required",
	"members.2fa_required_hint":  "This user cannot use scanX until 2FA is set up.",
	"members.2fa_require":        "Require 2FA",
	"members.2fa_require_hint":   "If 2FA is not on, the user is sent to set it up on their next request and cannot open other pages until done.",
	"members.2fa_unrequire":      "Make optional",
	"members.2fa_unrequire_hint": "The user may turn 2FA off again.",
	"members.reset_link":         "Password link",
	"members.reset_hint":         "Creates a one-time password reset link (valid for 24 hours).",
	"members.reset_confirm":      "Create a password reset link for %s? Their open sessions end when the new password is set.",
	"members.reset_created":      "Password reset link for %s created. It is valid for 24 hours and works once; it is shown only now, so pass it on over a secure channel.",
	"members.invite_2fa":         "Require 2FA",
	"members.invite_2fa_hint":    "The invitee must set up two-step verification when signing up.",
	"invite.require_2fa":         "This organization requires 2FA: after creating your account you will be asked to set up two-step verification with an authenticator app (Google/Microsoft Authenticator etc.).",
	"reset.title":                "Set a new password",
	"reset.body":                 "Set a new password for %s.",
	"reset.submit":               "Save password",
	"reset.note":                 "Saving ends all open sessions; log in again with the new password (and your 2FA code if enabled).",
	"flash.password_reset":       "Your password was updated. Log in with the new password.",
	"account.2fa_required_org":   "Your organization admin requires 2FA for this account, so it cannot be turned off.",
}

func init() {
	for k, v := range enSecurity {
		en[k] = v
	}
}
