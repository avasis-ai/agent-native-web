import { BRIDGE_REFUSAL_CODES, BridgeError } from './errors.mjs';
import {
  attribute,
  attributes,
  hasAttribute,
  nodeLocation,
  textContent,
  walkElements
} from './html-source.mjs';

export const AUTH_SIGNAL_KINDS = Object.freeze([
  'credential_form',
  'one_time_code',
  'magic_link',
  'passkey',
  'captcha',
  'oauth_authorization'
]);

const KNOWN_CAPTCHA_HOSTS = new Set([
  'www.google.com',
  'www.recaptcha.net',
  'hcaptcha.com',
  'js.hcaptcha.com',
  'challenges.cloudflare.com'
]);
const OTP_NAME = /(?:^|[_-])(?:otp|totp|mfa|2fa|verification[_-]?code|one[_-]?time[_-]?(?:code|password))(?:$|[_-])/i;
const MAGIC_LINK_TEXT = /(?:magic|email|sign[- ]?in|login)[- ]?link|(?:email|send)\s+(?:me\s+)?(?:a\s+)?link/i;
const PASSKEY_TEXT = /\b(?:passkey|security key|webauthn|authenticator)\b/i;
const MAX_AUTH_ELEMENTS = 50_000;

function invalidMetadata(detail) {
  return new BridgeError(BRIDGE_REFUSAL_CODES.AUTH_METADATA_INVALID, {
    detail,
    stage: 'auth'
  });
}

function compactText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim().slice(0, 240);
}

function evidence(kind, strength, message, node, details = {}, blocking = false, ownerOverride = undefined) {
  const owner = ownerOverride === undefined
    ? node?.tagName === 'form' ? node : nearestForm(node)
    : ownerOverride;
  const ownerLocation = nodeLocation(owner);
  return Object.freeze({
    kind,
    strength,
    blocking,
    message,
    source: 'static_html',
    ...(node ? { location: nodeLocation(node) } : {}),
    details: Object.freeze({
      ...details,
      ...(owner ? {
        form_context: Object.freeze({
          html_id: attribute(owner, 'id'),
          start_offset: ownerLocation?.start_offset ?? null
        })
      } : {})
    })
  });
}

function nearestForm(node) {
  for (let current = node?.parentNode; current; current = current.parentNode) {
    if (current.tagName === 'form') return current;
  }
  return null;
}

function parentElement(node) {
  let parent = node?.parentNode ?? null;
  while (parent && !parent.tagName) parent = parent.parentNode ?? null;
  return parent;
}

function isDescendantOf(node, ancestor) {
  for (let current = node?.parentNode; current; current = current.parentNode) {
    if (current === ancestor) return true;
  }
  return false;
}

function firstLegend(fieldset) {
  return (fieldset.childNodes ?? []).find((node) => node.tagName === 'legend') ?? null;
}

function autocompleteTokens(node) {
  return String(attribute(node, 'autocomplete') ?? '')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);
}

function safeUrl(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    url.hash = '';
    return url;
  } catch {
    return null;
  }
}

function captchaUrl(node, baseUrl) {
  if (!['script', 'iframe'].includes(node.tagName)) return null;
  const raw = attribute(node, 'src') ?? attribute(node, 'href');
  const url = raw ? safeUrl(raw, baseUrl) : null;
  if (!url || !KNOWN_CAPTCHA_HOSTS.has(url.hostname.toLowerCase())) return null;
  const integrationPath = url.hostname.toLowerCase().includes('hcaptcha.com')
    ? /(?:^|\/)(?:api\.js|captcha|1\/api\.js)(?:$|[/?])/i.test(url.pathname)
    : /\/(?:recaptcha|turnstile)(?:\/|$)/i.test(url.pathname);
  return integrationPath ? url : null;
}

function disabledByMarkup(node) {
  if (hasAttribute(node, 'disabled')) return true;
  for (let current = parentElement(node); current; current = parentElement(current)) {
    if (current.tagName !== 'fieldset' || !hasAttribute(current, 'disabled')) continue;
    const legend = firstLegend(current);
    if (!legend || !isDescendantOf(node, legend)) return true;
  }
  return false;
}

function oauthTargetCandidate(target, baseUrl, formParameters = []) {
  const url = target ? safeUrl(target, baseUrl) : null;
  if (!url) return null;
  const parameters = new URLSearchParams(url.search);
  for (const [name, value] of formParameters) parameters.append(name, value);
  const responseTypes = parameters.getAll('response_type');
  const codeRequested = responseTypes.some((value) => value.split(/\s+/).includes('code'));
  const hasOAuthShape = parameters.has('client_id')
    && (codeRequested || /\/(?:oauth2?|oidc)?\/?authorize\b/i.test(url.pathname));
  return hasOAuthShape ? {
    url,
    parameterNames: [...new Set(parameters.keys())],
    authorizationCodeRequested: codeRequested
  } : null;
}

function oauthCandidate(node, baseUrl, formParameters = [], targetOverride = undefined) {
  const raw = targetOverride === undefined
    ? attribute(node, 'href') ?? attribute(node, 'action')
    : targetOverride;
  const target = node.tagName === 'form' && (raw === null || raw.trim() === '') ? baseUrl : raw;
  return oauthTargetCandidate(target, baseUrl, formParameters);
}

function normalizedInputType(node) {
  const candidate = String(attribute(node, 'type') ?? 'text').toLowerCase();
  return candidate || 'text';
}

function normalizedButtonType(node) {
  const candidate = String(attribute(node, 'type') ?? 'submit').toLowerCase();
  return ['submit', 'reset', 'button'].includes(candidate) ? candidate : 'submit';
}

function isSubmitter(node) {
  return node.tagName === 'button'
    ? normalizedButtonType(node) === 'submit'
    : node.tagName === 'input' && ['submit', 'image'].includes(normalizedInputType(node));
}

function descendantOptions(select) {
  return [...walkElements(select)].filter((node) => node.tagName === 'option');
}

function optionDisabled(option) {
  if (hasAttribute(option, 'disabled')) return true;
  for (let current = parentElement(option); current; current = parentElement(current)) {
    if (current.tagName === 'optgroup') return hasAttribute(current, 'disabled');
    if (current.tagName === 'select') break;
  }
  return false;
}

function staticFormParameters(controls, selectedSubmitter) {
  const parameters = [];
  for (const control of controls) {
    if (disabledByMarkup(control)) continue;
    const name = attribute(control, 'name');
    if (!name) continue;
    if (isSubmitter(control)) {
      if (control !== selectedSubmitter) continue;
      parameters.push([name, attribute(control, 'value') ?? '']);
      continue;
    }
    if (control.tagName === 'input') {
      const type = normalizedInputType(control);
      if (['button', 'reset', 'file'].includes(type)) continue;
      if (['checkbox', 'radio'].includes(type) && !hasAttribute(control, 'checked')) continue;
      parameters.push([name, attribute(control, 'value') ?? '']);
      continue;
    }
    if (control.tagName === 'textarea') {
      parameters.push([name, textContent(control)]);
      continue;
    }
    if (control.tagName === 'select') {
      const options = descendantOptions(control);
      let selected = options.filter((option) => hasAttribute(option, 'selected') && !optionDisabled(option));
      if (!hasAttribute(control, 'multiple') && selected.length > 1) selected = [selected.at(-1)];
      if (!hasAttribute(control, 'multiple') && selected.length === 0) {
        const fallback = options.find((option) => !optionDisabled(option));
        if (fallback) selected = [fallback];
      }
      for (const option of selected) {
        parameters.push([name, attribute(option, 'value') ?? textContent(option)]);
      }
    }
  }
  return parameters;
}

export function detectOAuthAuthorizationRequest(target, parameters = []) {
  const candidate = oauthTargetCandidate(target, target, parameters);
  if (!candidate) return null;
  return Object.freeze({
    authorization_origin: candidate.url.origin,
    authorization_path: candidate.url.pathname,
    authorization_code_requested: candidate.authorizationCodeRequested
  });
}

function interactionFor(signal) {
  if (signal.strength !== 'direct') return null;
  const map = {
    one_time_code: ['AUTH_OTP_REQUIRED', 'provide_one_time_code'],
    passkey: ['AUTH_PASSKEY_REQUIRED', 'use_external_authenticator'],
    captcha: ['AUTH_CAPTCHA_REQUIRED', 'complete_human_challenge'],
    oauth_authorization: ['AUTH_EXTERNAL_USER_AGENT_REQUIRED', 'open_authorization_url']
  };
  const mapped = map[signal.kind];
  if (!mapped) return null;
  return Object.freeze({
    code: mapped[0],
    kind: mapped[1],
    blocking: signal.blocking === true,
    evidence_index: signal.index,
    ...(signal.details.form_context ? { form_context: signal.details.form_context } : {}),
    ...(signal.details.submitter_context ? { submitter_context: signal.details.submitter_context } : {}),
    ...(signal.details.authorization_origin ? {
      authorization_target: {
        origin: signal.details.authorization_origin,
        path: signal.details.authorization_path
      }
    } : {})
  });
}

/**
 * Extract authentication evidence from an inert parse5 tree. These are
 * observations and candidates, never proof that a user is authenticated.
 * Heuristic text matches are deliberately excluded from blocking decisions.
 */
export function discoverAuthSignals(source) {
  const document = source?.document ?? source;
  const sourceUrl = source?.source_url;
  if (!document || typeof document !== 'object') {
    throw new TypeError('discoverAuthSignals requires a parsed inert HTML source or parse5 document');
  }

  const elements = [...walkElements(document)];
  if (elements.length > MAX_AUTH_ELEMENTS) {
    return Object.freeze({
      kind: 'auth_evidence',
      authenticated: 'unverified',
      signals: Object.freeze([]),
      interaction_candidates: Object.freeze([]),
      required_interactions: Object.freeze([]),
      caveat: `Authentication discovery was skipped because the document exceeds ${MAX_AUTH_ELEMENTS} elements.`
    });
  }
  const formsByHtmlId = new Map();
  for (const node of elements) {
    if (node.tagName !== 'form') continue;
    const id = attribute(node, 'id');
    if (id && !formsByHtmlId.has(id)) formsByHtmlId.set(id, node);
  }
  const formOwner = (node) => hasAttribute(node, 'form')
    ? formsByHtmlId.get(attribute(node, 'form')) ?? null
    : nearestForm(node);
  const controlsByForm = new Map();
  for (const node of elements) {
    if (!['input', 'button', 'select', 'textarea'].includes(node.tagName)) continue;
    const owner = formOwner(node);
    if (!owner) continue;
    if (!controlsByForm.has(owner)) controlsByForm.set(owner, []);
    controlsByForm.get(owner).push(node);
  }
  const passwordForms = new Set();
  for (const [form, controls] of controlsByForm) {
    if (controls.some((node) => node.tagName === 'input'
      && String(attribute(node, 'type') ?? 'text').toLowerCase() === 'password'
      && !disabledByMarkup(node))) passwordForms.add(form);
  }

  const signals = [];
  const push = (value) => signals.push(Object.freeze({ ...value, index: signals.length }));
  for (const node of elements) {
    if (node.tagName === 'input') {
      const attrs = attributes(node);
      const type = String(attrs.type || 'text').toLowerCase();
      const autocomplete = autocompleteTokens(node);
      if (type === 'password' && !disabledByMarkup(node)) {
        const owner = formOwner(node);
        push(evidence('credential_form', 'direct', 'A standard password control is present.', node, {
          name: attrs.name || null,
          autocomplete
        }, false, owner));
      }
      if (autocomplete.includes('one-time-code') && !disabledByMarkup(node)) {
        const owner = formOwner(node);
        push(evidence('one_time_code', 'direct', 'A control explicitly declares autocomplete=one-time-code.', node, {
          name: attrs.name || null
        }, Boolean(owner && hasAttribute(node, 'required')), owner));
      } else if (OTP_NAME.test(attrs.name || '')) {
        push(evidence('one_time_code', 'heuristic', 'A control name resembles a one-time-code field.', node, {
          name: attrs.name
        }));
      }
      if (autocomplete.includes('webauthn') && !disabledByMarkup(node)) {
        const owner = formOwner(node);
        const passwordFallbackPresent = Boolean(owner && passwordForms.has(owner));
        push(evidence('passkey', 'direct', 'A control explicitly declares WebAuthn conditional mediation.', node, {
          name: attrs.name || null,
          password_fallback_present: passwordFallbackPresent
        }, Boolean(owner && !passwordFallbackPresent), owner));
      }
    }

    const captcha = captchaUrl(node, sourceUrl);
    if (captcha || hasAttribute(node, 'data-sitekey') && /(?:captcha|turnstile)/i.test(`${attribute(node, 'class') ?? ''} ${attribute(node, 'id') ?? ''}`)) {
      const widgetInForm = Boolean(nearestForm(node));
      push(evidence('captcha', 'direct', 'Static markup references a known CAPTCHA integration.', node, {
        provider_host: captcha?.hostname ?? null,
        site_key_present: hasAttribute(node, 'data-sitekey')
      }, widgetInForm));
    }

    if (node.tagName === 'a') {
      const candidate = oauthCandidate(node, sourceUrl);
      if (candidate) {
        push(evidence('oauth_authorization', 'direct', 'Markup contains an OAuth authorization-code request candidate.', node, {
          authorization_origin: candidate.url.origin,
          authorization_path: candidate.url.pathname,
          query_parameter_names: candidate.parameterNames,
          authorization_code_requested: candidate.authorizationCodeRequested
        }));
      }
    }

    if (['button', 'a', 'label', 'p'].includes(node.tagName)) {
      const visibleText = compactText(textContent(node, { excludeControls: true }));
      if (visibleText && PASSKEY_TEXT.test(visibleText)) {
        push(evidence('passkey', 'heuristic', 'Visible source text mentions a passkey or authenticator.', node, {
          matched_category: 'passkey_or_authenticator'
        }));
      }
      if (visibleText && MAGIC_LINK_TEXT.test(visibleText)) {
        push(evidence('magic_link', 'heuristic', 'Visible source text resembles a magic-link flow.', node, {
          matched_category: 'magic_link'
        }));
      }
    }
  }

  for (const form of elements.filter((node) => node.tagName === 'form')) {
    const controls = controlsByForm.get(form) ?? [];
    const submitters = controls.filter((control) => isSubmitter(control) && !disabledByMarkup(control));
    const variants = submitters.length ? submitters : [null];
    for (const submitter of variants) {
      const formAction = attribute(form, 'action');
      const target = submitter && hasAttribute(submitter, 'formaction')
        ? attribute(submitter, 'formaction')
        : formAction;
      const candidate = oauthCandidate(form, sourceUrl, staticFormParameters(controls, submitter), target);
      if (!candidate) continue;
      const submitterLocation = nodeLocation(submitter);
      push(evidence('oauth_authorization', 'direct', 'An effective form submitter produces an OAuth authorization request candidate.', submitter ?? form, {
        authorization_origin: candidate.url.origin,
        authorization_path: candidate.url.pathname,
        query_parameter_names: candidate.parameterNames,
        authorization_code_requested: candidate.authorizationCodeRequested,
        ...(submitter ? {
          submitter_context: {
            start_offset: submitterLocation?.start_offset ?? null
          }
        } : {})
      }, true, form));
    }
  }

  const interactions = signals.map(interactionFor).filter(Boolean);
  return Object.freeze({
    kind: 'auth_evidence',
    authenticated: 'unverified',
    signals: Object.freeze(signals),
    interaction_candidates: Object.freeze(interactions),
    required_interactions: Object.freeze(interactions.filter((item) => item.blocking)),
    caveat: 'Static HTML can expose transport controls, but it cannot prove the authenticated subject or successful authentication.'
  });
}

function metadataUrl(value, label) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw invalidMetadata(`${label} must be an absolute URL.`);
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) {
    throw invalidMetadata(`${label} must be an HTTPS URL without userinfo or a fragment.`);
  }
  return url.href;
}

/** Validate a conservative subset of RFC 8414 / OpenID metadata. */
export function validateAuthorizationServerMetadata(metadata, { metadataUrl: sourceUrl } = {}) {
  if (!metadata || typeof metadata !== 'object' || Array.isArray(metadata)) {
    throw invalidMetadata('Authorization server metadata must be a JSON object.');
  }
  const issuer = metadataUrl(metadata.issuer, 'issuer');
  const authorizationEndpoint = metadataUrl(metadata.authorization_endpoint, 'authorization_endpoint');
  const tokenEndpoint = metadata.token_endpoint === undefined
    ? null
    : metadataUrl(metadata.token_endpoint, 'token_endpoint');
  if (sourceUrl !== undefined) metadataUrl(sourceUrl, 'metadataUrl');

  const responseTypes = Array.isArray(metadata.response_types_supported)
    ? metadata.response_types_supported.filter((value) => typeof value === 'string')
    : [];
  const pkceMethods = Array.isArray(metadata.code_challenge_methods_supported)
    ? metadata.code_challenge_methods_supported.filter((value) => typeof value === 'string')
    : [];

  return Object.freeze({
    kind: 'authorization_server_metadata',
    issuer,
    authorization_endpoint: authorizationEndpoint,
    ...(tokenEndpoint ? { token_endpoint: tokenEndpoint } : {}),
    authorization_code_supported: responseTypes.some((value) => value.split(/\s+/).includes('code')),
    pkce_s256_advertised: pkceMethods.includes('S256'),
    interaction: Object.freeze({
      code: BRIDGE_REFUSAL_CODES.AUTH_EXTERNAL_USER_AGENT_REQUIRED,
      kind: 'open_authorization_url',
      reason: 'Authorization-code user interaction belongs in an external user-agent; the HTTP bridge does not scrape or emulate the login UI.'
    })
  });
}

export function authorizationMetadataCandidates(origin) {
  const url = new URL(origin);
  if (url.protocol !== 'https:' || url.username || url.password) {
    throw invalidMetadata('Metadata discovery requires an HTTPS origin.');
  }
  return Object.freeze([
    new URL('/.well-known/openid-configuration', url.origin).href,
    new URL('/.well-known/oauth-authorization-server', url.origin).href
  ]);
}
