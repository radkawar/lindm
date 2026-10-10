package devlab

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp/totp"
)

// entraMFA belongs to exactly one disposable fixture identity. It must never be
// serialized or logged. Registration is performed through Microsoft's genuine
// security-info UI; no tenant policy or authentication requirement is weakened.
// The fixture retains this state only so a second fresh login can prove TOTP.
type entraMFA struct {
	username    string
	secret      string
	lastStage   string
	lastAction  string
	diagnostics string
}

func (m *entraMFA) bind(username string) error {
	if username == "" || (m.username != "" && m.username != username) {
		return errors.New("entra: MFA state belongs to another identity")
	}
	m.username = username
	m.lastStage, m.lastAction, m.diagnostics = "not_observed", "none", "not_observed"
	return nil
}

func entraBlockedHost(endpoint *url.URL) string {
	if endpoint == nil {
		return "invalid_url"
	}
	switch endpoint.Host {
	case "graph.microsoft.com", "mysignins.microsoft.com", "login.microsoftonline.com",
		"login.microsoft.com", "login.live.com", "account.activedirectory.windowsazure.com",
		"enterpriseregistration.windows.net", "aadcdn.msftauthimages.net",
		"aadcdn.msauthimages.net", "static2.sharepointonline.com", "alcdn.msauth.net",
		"account.microsoft.com", "registration.windows.net":
		return endpoint.Host
	default:
		return "unrecognized_off_origin"
	}
}

func (c *entraCDP) mfaDiagnosticError(mfa *entraMFA, err error) error {
	blocked := "none"
	if len(c.blockedRequests) != 0 {
		blocked = strings.Join(c.blockedRequests, ",")
	}
	return fmt.Errorf("%w (mfa_stage=%s last_action=%s page=%s blocked=%s)", err,
		mfa.lastStage, mfa.lastAction, mfa.diagnostics, blocked)
}

func entraTOTPSecret(raw string) (string, error) {
	secret := strings.ToUpper(strings.Join(strings.Fields(raw), ""))
	if len(secret) < 16 || len(secret) > 128 {
		return "", errors.New("entra: security-info returned an invalid TOTP secret")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	defer clear(decoded)
	if err != nil || len(decoded) < 10 || len(decoded) > 80 {
		return "", errors.New("entra: security-info returned an invalid TOTP secret")
	}
	return secret, nil
}

// Only manual-entry controls are inspected. QR image data and activation URLs
// are deliberately excluded: Microsoft push activation is not a TOTP secret.
const entraManualSecretProbe = `() => {
	if (!['https://login.microsoftonline.com','https://mysignins.microsoft.com'].includes(location.origin) || !document.body) return {seen:false,secret:''};
	const visible = e => e && e.checkVisibility({opacityProperty:true,visibilityProperty:true}) && e.getClientRects().length;
	const keyLabel = /^(secret key|secret|key)\s*:?\s*$/i;
	const candidates = new Set();
	let seen = false;
	const add = raw => {
		const value = (raw || '').replace(/\s+/g,'').toUpperCase();
		if (/^[A-Z2-7]{16,128}$/.test(value)) candidates.add(value);
	};
	const text = document.body.innerText.slice(0,32768);
	for (const match of text.matchAll(/(?:^|\n)\s*(?:secret key|secret|key)(?:[ \t]*:\s*|[ \t]*\n[ \t]*)([A-Z2-7][A-Z2-7 \t]{15,127})(?=\n|$)/gi)) {
		seen = true;
		add(match[1]);
	}
	const valueOf = e => e && visible(e) ? (e instanceof HTMLInputElement || e instanceof HTMLTextAreaElement ? e.value : e.innerText) : '';
	for (const input of [...document.querySelectorAll('input,textarea')].slice(0,128)) {
		if (!visible(input) || input.type === 'password' || input.type === 'hidden') continue;
		const labels = [...(input.labels || [])].map(e => e.innerText);
		labels.push(input.getAttribute('aria-label') || '', input.name || '', input.id || '');
		const labelled = labels.some(value => keyLabel.test(value));
		if (labelled) seen = true;
		if (labelled || input.readOnly) add(input.value);
	}
	for (const label of [...document.querySelectorAll('label,dt,span,div,p,strong,b')].slice(0,1024)) {
		if (!visible(label) || !keyLabel.test(label.innerText || '')) continue;
		seen = true;
		add(valueOf(label.nextElementSibling));
		add(valueOf(label.parentElement?.nextElementSibling));
		if (label instanceof HTMLLabelElement && label.control) add(valueOf(label.control));
		const input = label.parentElement?.querySelector('input,textarea');
		if (input) add(valueOf(input));
	}
	return {seen:seen || candidates.size > 0, secret:candidates.size === 1 ? [...candidates][0] : '', ambiguous:candidates.size > 1};
}`

// The probe returns a small fixed stage and, on the secret-key page only, the
// enrollment secret. No HTML, screenshots, QR images or upstream error strings
// are returned. Every action rechecks both the stage and the exact HTTPS origin.
const entraMFAProbe = `() => {
	if (!['https://login.microsoftonline.com','https://mysignins.microsoft.com'].includes(location.origin)) return {stage:'untrusted'};
	if (!document.body) return {stage:'loading'};
	const text = document.body.innerText;
	const visible = e => e && !e.disabled && e.checkVisibility({opacityProperty:true,visibilityProperty:true}) && e.getClientRects().length;
	const controls = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')].filter(visible);
	const label = e => (e.innerText || e.value || e.getAttribute('aria-label') || '').replace(/\s+/g,' ').trim();
	const control = pattern => controls.find(e => pattern.test(label(e)));
	const result = (stage, button, input, secret) => ({stage, button, input, secret});
	const code = [...document.querySelectorAll('input')].find(e => visible(e) && (e.name === 'otc' || e.id === 'idTxtBx_SAOTCC_OTC' || e.autocomplete === 'one-time-code' || /verification code|enter (the )?code|6.digit code|^code$/i.test([e.placeholder,e.getAttribute('aria-label'),...(e.labels || [])].map(v => typeof v === 'string' ? v : v?.innerText || '').filter(Boolean).join(' '))));
	if (/incorrect code|invalid code|code is incorrect|code you entered.*(incorrect|invalid)|verification failed/i.test(text)) return {stage:'code_rejected'};
	if (/conditional access|you can't get there from here|AADSTS530\d+/i.test(text)) return {stage:'conditional_access'};
	if (/need admin approval|permissions requested|AADSTS65001/i.test(text)) return {stage:'consent_required'};
	if (/change your password|update your password|AADSTS50055/i.test(text)) return {stage:'password_change_required'};
	if (code && control(/^(verify|next|sign in)$/i)) return result(location.origin === 'https://mysignins.microsoft.com' ? 'enrollment_code' : 'challenge_code', control(/^(verify|next|sign in)$/i), code);
	const different = control(/^(i want to use a different authenticator app|use a different authenticator app)$/i);
	if (different) return result('different_app', different);
	const enrollment = (` + entraManualSecretProbe + `)();
	if (enrollment.seen) {
		if (enrollment.secret && control(/^next$/i)) return result('secret', control(/^next$/i), null, enrollment.secret);
		return {stage:'secret_unavailable'};
	}
	const manual = control(/^(can.t scan (the )?(image|qr code)\??|unable to scan (the )?(image|qr code)\??)$/i);
	if (manual) return result('show_secret', manual);
	if (/set up your account/i.test(text) && control(/^next$/i)) return result('setup_account', control(/^next$/i));
	if (/scan (the )?qr code|scan (the )?image/i.test(text) && control(/^next$/i)) return result('scan', control(/^next$/i));
	if (/success|successfully|all set|great job/i.test(text) && control(/^(done|finish|next)$/i)) return result('complete_registration', control(/^(done|finish|next)$/i));
	if (location.origin === 'https://mysignins.microsoft.com' && /start by getting (the )?app|set up microsoft authenticator|microsoft authenticator/i.test(text) && control(/^next$/i)) return result('authenticator_setup', control(/^next$/i));
	if (/more information required|keep your account secure|security defaults|protect your account/i.test(text) && control(/^next$/i)) return result('start_registration', control(/^next$/i));
	const other = control(/^(i can.t use my microsoft authenticator app right now|sign in another way)$/i);
	if (other) return result('choose_code', other);
	const option = control(/^(use a verification code|verification code|enter a code from an authenticator app)$/i);
	if (option) return result('select_code', option);
	if (/approve.*(sign.in|request)|check your.*authenticator/i.test(text)) return {stage:'push_unavailable'};
	if (/phone|text message|call me/i.test(text) && /add|enter|set up|verify/i.test(text)) return {stage:'unsupported_phone_registration'};
	return {stage:'loading'};
}`

// These labels are closed vocabulary, not page text. Unknown observations never
// pass through diagnostics, even if the DOM or a browser response is unexpected.
func entraMFADiagnostics(labels []string) string {
	var safe []string
	for _, label := range labels {
		switch label {
		case "login_origin", "security_info_origin", "unknown_origin", "no_document",
			"authenticator_setup", "get_app", "keep_secure", "more_information",
			"registration_required", "organization_requires", "security_defaults",
			"setup_account", "scan_qr", "secret_key", "code_prompt", "success",
			"next_control", "continue_control", "different_app_control", "different_method_control",
			"manual_key_control", "skip_control", "done_control", "code_input",
			"manual_setup", "account_name", "secret_label", "activation_code_label", "activation_url_label", "readonly_secret_candidate",
			"security_info_home", "error_page", "empty_body", "unknown_page":
			safe = append(safe, label)
		}
		if len(safe) == 32 {
			break
		}
	}
	if len(safe) == 0 {
		return "unknown_page"
	}
	return strings.Join(safe, ",")
}

const entraMFADiagnosticProbe = `() => {
	const categories = [];
	categories.push(location.origin === 'https://login.microsoftonline.com' ? 'login_origin' :
		location.origin === 'https://mysignins.microsoft.com' ? 'security_info_origin' : 'unknown_origin');
	if (!document.body) return [...categories,'no_document'];
	const text = document.body.innerText.slice(0,32768);
	const pageCategories = [
		['authenticator_setup',/microsoft authenticator/i], ['get_app',/start by getting the app|get the app/i],
		['keep_secure',/keep your account secure|protect your account/i], ['more_information',/more information required/i],
		['registration_required',/registration.*required|register.*security|set up.*security/i],
		['organization_requires',/organization.*(requires|needs)|required by.*organization/i],
		['security_defaults',/security defaults/i], ['setup_account',/set up your account/i],
		['scan_qr',/scan.*(qr|image)/i], ['secret_key',/secret key/i],
		['manual_setup',/manually|manual setup|enter.*(key|details)/i], ['account_name',/account name/i],
		['secret_label',/(?:^|\n)\s*(?:secret key|secret|key)\s*:?/i],
		['activation_code_label',/(?:^|\n)\s*(?:activation code|code)\s*:/i],
		['activation_url_label',/(?:^|\n)\s*(?:activation url|url)\s*:/i],
		['code_prompt',/enter.*code/i], ['success',/success|all set|great job/i],
		['security_info_home',/security info.*|add sign.in method/i], ['error_page',/something went wrong|sorry|error|AADSTS[0-9]+/i]
	];
	for (const [category,pattern] of pageCategories) if (pattern.test(text)) categories.push(category);
	const controls = [...document.querySelectorAll('button,a,input[type="submit"],[role="button"],[role="link"]')]
		.filter(e => e.checkVisibility({opacityProperty:true,visibilityProperty:true})).slice(0,64)
		.map(e => (e.innerText || e.value || e.getAttribute('aria-label') || '').replace(/\s+/g,' ').trim());
	for (const [category,pattern] of [
		['next_control',/^next$/i], ['continue_control',/^continue$/i],
		['different_app_control',/different authenticator app/i], ['different_method_control',/different method|another way/i],
		['manual_key_control',/can.t scan|unable to scan/i], ['skip_control',/skip|not now|later/i],
		['done_control',/^(done|finish)$/i]
	]) if (controls.some(label => pattern.test(label))) categories.push(category);
	if ([...document.querySelectorAll('input')].some(e => e.checkVisibility() && (e.name === 'otc' || e.autocomplete === 'one-time-code'))) categories.push('code_input');
	if ([...document.querySelectorAll('input[readonly],textarea[readonly]')].some(e => e.checkVisibility() && /^[A-Z2-7]{16,128}$/i.test(e.value.replace(/\s+/g,'')))) categories.push('readonly_secret_candidate');
	if (!text.trim()) categories.push('empty_body');
	if (categories.length === 1) categories.push('unknown_page');
	return categories;
}`

func (c *entraCDP) continueMFA(ctx context.Context, mfa *entraMFA, actions map[string]bool) error {
	var page struct {
		Stage       string   `json:"stage"`
		Secret      string   `json:"secret"`
		Diagnostics []string `json:"diagnostics"`
	}
	if err := c.evaluate(ctx, `(() => { const p = (`+entraMFAProbe+`)(); return {stage:p.stage,secret:p.secret || '',diagnostics:(`+entraMFADiagnosticProbe+`)()}; })()`, &page); err != nil {
		return err
	}
	mfa.diagnostics = entraMFADiagnostics(page.Diagnostics)
	switch page.Stage {
	case "loading":
		mfa.lastStage = page.Stage
		return nil
	case "untrusted", "conditional_access", "consent_required", "password_change_required", "code_rejected", "push_unavailable", "unsupported_phone_registration", "secret_unavailable":
		mfa.lastStage = page.Stage
		return fmt.Errorf("entra: software TOTP continuation interrupted (%s)", page.Stage)
	case "start_registration", "authenticator_setup", "different_app", "show_secret", "setup_account", "secret", "scan", "enrollment_code", "challenge_code", "complete_registration", "choose_code", "select_code":
		mfa.lastStage = page.Stage
	default:
		return errors.New("entra: unsupported software TOTP registration stage")
	}
	if actions[page.Stage] {
		return nil
	}
	if page.Stage == "secret" {
		secret, err := entraTOTPSecret(page.Secret)
		page.Secret = ""
		if err != nil {
			return err
		}
		if mfa.secret != "" && mfa.secret != secret {
			return errors.New("entra: refusing to replace existing fixture TOTP enrollment")
		}
		mfa.secret = secret
	}
	if page.Stage == "scan" && mfa.secret == "" {
		return errors.New("entra: software TOTP enrollment requires the manual secret-key link")
	}
	code := ""
	if page.Stage == "enrollment_code" || page.Stage == "challenge_code" {
		if mfa.secret == "" {
			return errors.New("entra: MFA requested a code without owned software TOTP enrollment")
		}
		// Do not submit a code about to expire. This is an observation wait, not
		// a retry of a security mutation or rejected authentication attempt.
		now := time.Now()
		if now.Unix()%30 >= 25 {
			return nil
		}
		var err error
		code, err = totp.GenerateCode(mfa.secret, now)
		if err != nil {
			return errors.New("entra: generate owned software TOTP code failed")
		}
	}
	args, err := json.Marshal([]string{page.Stage, code})
	if err != nil {
		return errors.New("entra: encode software TOTP action failed")
	}
	defer clear(args)
	var submitted bool
	expression := `(([expected,code]) => {
		const p = (` + entraMFAProbe + `)();
		if (p.stage !== expected || !p.button) return false;
		if (p.input) {
			if (p.input.form && new URL(p.input.form.action,location.href).origin !== location.origin) return false;
			Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(p.input,code);
			p.input.dispatchEvent(new Event('input',{bubbles:true}));
			p.input.dispatchEvent(new Event('change',{bubbles:true}));
		}
		p.button.click();
		return true;
	})(` + string(args) + `)`
	// Mark before dispatch: document replacement must never repeat an action.
	actions[page.Stage] = true
	mfa.lastAction = page.Stage
	if err := c.evaluate(ctx, expression, &submitted); err != nil {
		return err
	}
	if !submitted {
		return errors.New("entra: software TOTP page changed before action")
	}
	return nil
}
