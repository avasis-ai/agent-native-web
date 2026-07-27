import { createHash } from 'node:crypto';
import { ASSURANCE_LEVELS, createAssuranceVector } from './assurance.mjs';
import { BRIDGE_REFUSAL_CODES, BridgeError } from './errors.mjs';
import {
  attribute,
  hasAttribute,
  nodeLocation,
  textContent,
  walkElements
} from './html-source.mjs';
import {
  HTTP_BRIDGE_PROFILE,
  HTTP_BRIDGE_PROFILE_VERSION,
  HTTP_BRIDGE_PROTOCOL,
  HTTP_BRIDGE_PROTOCOL_VERSION
} from './profile.mjs';

const FORM_CONTROLS = new Set(['input', 'button', 'select', 'textarea']);
const TEXT_INPUT_TYPES = new Set([
  'text', 'search', 'tel', 'url', 'email', 'password', 'number', 'range',
  'date', 'month', 'week', 'time', 'datetime-local', 'color'
]);
const NON_SUBMITTING_INPUT_TYPES = new Set(['button', 'reset']);
const UNSUPPORTED_TEMPORAL_INPUT_TYPES = new Set(['date', 'month', 'week', 'time', 'datetime-local']);
const IMPLICIT_SUBMISSION_BLOCKERS = new Set([
  'text', 'search', 'tel', 'url', 'email', 'password', 'date', 'month',
  'week', 'time', 'datetime-local', 'number'
]);
const SEMANTIC_ATTRIBUTES = new Set([
  'alt', 'class', 'closedby', 'command', 'commandfor', 'dir', 'hidden',
  'inert', 'lang', 'open', 'popover', 'role', 'style', 'tabindex', 'title'
]);
const URL_ENCODED = 'application/x-www-form-urlencoded';
const HTML_EMAIL = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
const URI_SCHEME = '[A-Za-z][A-Za-z0-9+.-]*';
const URI_UNRESERVED = '[A-Za-z0-9._~-]';
const URI_PCT_ENCODED = '%[0-9A-Fa-f]{2}';
const URI_SUB_DELIM = "[!$&'()*+,;=]";
const URI_PCHAR = `(?:${URI_UNRESERVED}|${URI_PCT_ENCODED}|${URI_SUB_DELIM}|[:@])`;
const URI_SEGMENT = `${URI_PCHAR}*`;
const URI_SEGMENT_NONEMPTY = `${URI_PCHAR}+`;
const URI_USERINFO_CHAR = `(?:${URI_UNRESERVED}|${URI_PCT_ENCODED}|${URI_SUB_DELIM}|:)`;
const URI_REG_NAME_CHAR = `(?:${URI_UNRESERVED}|${URI_PCT_ENCODED}|${URI_SUB_DELIM})`;
const URI_AUTHORITY = `(?:(?:${URI_USERINFO_CHAR}*@)?${URI_REG_NAME_CHAR}+(?::[0-9]*)?)?`;
const URI_QUERY_CHAR = `(?:${URI_PCHAR}|[/?])`;
const URI_HIER_PART = `(?:(?:\\/\\/${URI_AUTHORITY}(?:\\/${URI_SEGMENT})*)|(?:\\/(?:${URI_SEGMENT_NONEMPTY}(?:\\/${URI_SEGMENT})*)?)|(?:${URI_SEGMENT_NONEMPTY}(?:\\/${URI_SEGMENT})*))?`;
const ABSOLUTE_URI_PATTERN = `^${URI_SCHEME}:${URI_HIER_PART}(?:\\?${URI_QUERY_CHAR}*)?(?:#${URI_QUERY_CHAR}*)?$`;
const NETWORK_SCHEME = '(?:[Hh][Tt][Tt][Pp][Ss]?|[Ww][Ss][Ss]?|[Ff][Tt][Pp])';
const NETWORK_SCHEME_PREFIX_PATTERN = `^${NETWORK_SCHEME}:`;
const IPV4_OCTET = '(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])';
const IPV4_HOST = `${IPV4_OCTET}(?:\\.${IPV4_OCTET}){3}`;
const DNS_LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const DNS_HOST = `(?=[A-Za-z0-9.-]{1,253}(?::|\\/|\\?|#|$))(?=[A-Za-z0-9.-]*[A-Za-z])${DNS_LABEL}(?:\\.${DNS_LABEL})*\\.?`;
const NETWORK_HOST = `(?:${IPV4_HOST}|${DNS_HOST})`;
const NETWORK_PORT = '(?:[0-9]{1,4}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])';
const NETWORK_URI_PATTERN = `^${NETWORK_SCHEME}:\\/\\/${NETWORK_HOST}(?::(?:${NETWORK_PORT})?)?(?:\\/${URI_SEGMENT})*(?:\\?${URI_QUERY_CHAR}*)?(?:#${URI_QUERY_CHAR}*)?$`;
const ABSOLUTE_URI = new RegExp(ABSOLUTE_URI_PATTERN, 'u');
const NETWORK_SCHEME_PREFIX = new RegExp(NETWORK_SCHEME_PREFIX_PATTERN, 'u');
const NETWORK_URI = new RegExp(NETWORK_URI_PATTERN, 'u');
const MAX_INFERENCE_ELEMENTS = 50_000;

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function digest(value, length = 64) {
  return createHash('sha256').update(typeof value === 'string' ? value : canonical(value)).digest('hex').slice(0, length);
}

function normalizedText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim();
}

function stripAndCollapseAsciiWhitespace(value) {
  return String(value ?? '')
    .replace(/[\t\n\f\r ]+/g, ' ')
    .replace(/^[\t\n\f\r ]+|[\t\n\f\r ]+$/g, '');
}

function textEvidence(value) {
  const normalized = normalizedText(value);
  return Object.freeze({
    text: normalized.slice(0, 500),
    semantics_digest: `sha256:${digest(normalized)}`,
    present: normalized.length > 0
  });
}

function combineTextEvidence(items, separator = ' / ') {
  const present = items.filter((item) => item?.present);
  if (!present.length) return textEvidence('');
  if (present.length === 1) return present[0];

  let display = '';
  for (const item of present) {
    if (display.length >= 500) break;
    const fragment = display ? `${separator}${item.text}` : item.text;
    display += fragment.slice(0, 500 - display.length);
  }
  const hash = createHash('sha256');
  hash.update('agent-native-web:text-evidence:v1\0');
  for (const item of present) hash.update(`${item.semantics_digest}\0`);
  return Object.freeze({
    text: display,
    semantics_digest: `sha256:${hash.digest('hex')}`,
    present: true
  });
}

function semanticTreeDigest(root, { excludeControls = false } = {}) {
  const hash = createHash('sha256');
  hash.update('agent-native-web:semantic-tree:v1\0');
  const stack = [{ node: root, closing: false }];
  while (stack.length) {
    const { node, closing } = stack.pop();
    if (!node?.tagName) continue;
    if (excludeControls && FORM_CONTROLS.has(node.tagName) && node !== root) continue;
    if (node.tagName === 'script' || node.tagName === 'style') continue;
    if (closing) {
      hash.update(`</${node.tagName}>\0`);
      continue;
    }
    hash.update(`<${node.tagName}>\0`);
    const semanticAttributes = (node.attrs ?? [])
      .filter((item) => SEMANTIC_ATTRIBUTES.has(item.name.toLowerCase()) || item.name.toLowerCase().startsWith('aria-'))
      .map((item) => [item.name.toLowerCase(), item.value])
      .sort(([left], [right]) => left.localeCompare(right));
    for (const [name, value] of semanticAttributes) hash.update(`${name}\0${value}\0`);
    stack.push({ node, closing: true });
    const children = node.childNodes ?? [];
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: children[index], closing: false });
    }
  }
  return `sha256:${hash.digest('hex')}`;
}

function reviewTextContent(root, { excludeControls = false } = {}) {
  const chunks = [];
  const stack = [root];
  while (stack.length) {
    const node = stack.pop();
    if (node?.nodeName === '#text') {
      chunks.push(node.value ?? '');
      continue;
    }
    if (node?.tagName === 'script' || node?.tagName === 'style') continue;
    if (excludeControls && FORM_CONTROLS.has(node?.tagName) && node !== root) continue;
    if (node?.tagName === 'img') {
      const alt = attribute(node, 'alt');
      if (alt) chunks.push(` ${alt} `);
    }
    const children = node?.childNodes ?? [];
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
  return chunks.join('');
}

function finding(code, message, {
  scope = 'form',
  blocking = true,
  severity = blocking ? 'error' : 'warning',
  node = null,
  formId,
  actionId,
  fieldId,
  details
} = {}) {
  return {
    code,
    kind: blocking ? 'unsupported' : 'warning',
    scope,
    severity,
    blocking,
    message,
    ...(nodeLocation(node) ? { location: nodeLocation(node) } : {}),
    ...(formId ? { form_id: formId } : {}),
    ...(actionId ? { action_id: actionId } : {}),
    ...(fieldId ? { field_id: fieldId } : {}),
    ...(details === undefined ? {} : { details })
  };
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

function nearestAncestor(node, tagName) {
  for (let current = node?.parentNode; current; current = current.parentNode) {
    if (current.tagName === tagName) return current;
  }
  return null;
}

function firstLegend(fieldset) {
  return (fieldset.childNodes ?? []).find((node) => node.tagName === 'legend') ?? null;
}

function isDisabled(control) {
  if (hasAttribute(control, 'disabled')) return true;
  for (let ancestor = parentElement(control); ancestor; ancestor = parentElement(ancestor)) {
    if (ancestor.tagName !== 'fieldset' || !hasAttribute(ancestor, 'disabled')) continue;
    const legend = firstLegend(ancestor);
    if (!legend || !isDescendantOf(control, legend)) return true;
  }
  return false;
}

function optionDisabled(option) {
  if (hasAttribute(option, 'disabled')) return true;
  const group = nearestAncestor(option, 'optgroup');
  return Boolean(group && hasAttribute(group, 'disabled'));
}

function hasInlineHandler(node) {
  return Boolean(node?.attrs?.some((candidate) => candidate.name.toLowerCase().startsWith('on')));
}

function isExecutableScript(node) {
  const type = String(attribute(node, 'type') ?? '').trim().toLowerCase();
  return type === ''
    || type === 'module'
    || /^(?:text|application)\/(?:java|ecma)script(?:1\.[0-5])?$/.test(type);
}

function normalizeInputType(node) {
  const candidate = (attribute(node, 'type') || 'text').toLowerCase();
  if (TEXT_INPUT_TYPES.has(candidate) || ['hidden', 'checkbox', 'radio', 'file', 'submit', 'image', 'button', 'reset'].includes(candidate)) return candidate;
  return 'text';
}

function normalizeButtonType(node) {
  const candidate = String(attribute(node, 'type') ?? '').toLowerCase();
  if (['submit', 'reset', 'button'].includes(candidate)) {
    if (candidate === 'submit' && parentElement(node)?.tagName === 'select') return 'button';
    return candidate;
  }
  const autoSubmits = parentElement(node)?.tagName !== 'select'
    && !hasAttribute(node, 'command')
    && !hasAttribute(node, 'commandfor');
  return autoSubmits ? 'submit' : 'button';
}

function isSubmitButtonElement(node) {
  if (node.tagName === 'button') return normalizeButtonType(node) === 'submit';
  if (node.tagName !== 'input') return false;
  return ['submit', 'image'].includes(normalizeInputType(node));
}

function normalizeMethod(value) {
  const candidate = String(value || 'get').toLowerCase();
  if (['get', 'post', 'dialog'].includes(candidate)) return candidate;
  return 'get';
}

function normalizeEnctype(value) {
  const candidate = String(value || URL_ENCODED).toLowerCase();
  if ([URL_ENCODED, 'multipart/form-data', 'text/plain'].includes(candidate)) return candidate;
  return URL_ENCODED;
}

function normalizeNewlines(value) {
  return String(value).replace(/\r\n|\r|\n/g, '\r\n');
}

function readonlyInputValue(type, value) {
  const withoutNewlines = String(value).replace(/[\r\n]/g, '');
  return ['url', 'email'].includes(type)
    ? withoutNewlines.replace(/^[\t\f ]+|[\t\f ]+$/g, '')
    : withoutNewlines;
}

function numericAttribute(node, name, { integer = false, minimum = -Infinity } = {}) {
  const raw = attribute(node, name);
  if (raw === null || raw.trim() === '') return null;
  const value = Number(raw);
  if (!Number.isFinite(value) || value < minimum || (integer && !Number.isInteger(value))) return null;
  return value;
}

function constraintsFor(node, inputType) {
  const constraints = {
    required: hasAttribute(node, 'required'),
    readonly: hasAttribute(node, 'readonly'),
    ...(hasAttribute(node, 'multiple') ? { multiple: true } : {}),
    ...(attribute(node, 'autocomplete') ? { autocomplete: attribute(node, 'autocomplete') } : {})
  };
  const minLength = numericAttribute(node, 'minlength', { integer: true, minimum: 0 });
  const maxLength = numericAttribute(node, 'maxlength', { integer: true, minimum: 0 });
  if (minLength !== null) constraints.min_length = minLength;
  if (maxLength !== null) constraints.max_length = maxLength;
  for (const name of ['pattern', 'min', 'max', 'step', 'accept', 'inputmode']) {
    const value = attribute(node, name);
    if (value !== null && value !== '') constraints[name] = value;
  }
  if (inputType) constraints.html_type = inputType;
  return constraints;
}

function schemaForField(field) {
  const title = field.label || field.wire_name;
  if (field.kind === 'checkbox') {
    return {
      type: 'boolean',
      title,
      ...(field.required ? { const: true } : {})
    };
  }
  if (field.kind === 'radio' || field.kind === 'select-one') {
    const available = field.options.filter((option) => !option.disabled
      && !(field.kind === 'select-one' && field.required && option.placeholder));
    const canOmit = !field.required;
    return {
      type: canOmit ? ['string', 'null'] : 'string',
      title,
      enum: [...available.map((option) => option.option_id), ...(canOmit ? [null] : [])]
    };
  }
  if (field.kind === 'select-multiple') {
    const available = field.options.filter((option) => !option.disabled);
    return {
      type: 'array',
      title,
      uniqueItems: true,
      ...(field.required ? { minItems: 1 } : {}),
      items: { type: 'string', enum: available.map((option) => option.option_id) }
    };
  }
  if (['number', 'range'].includes(field.html_type)) {
    const schema = { type: 'number', title };
    const minimum = Number(field.constraints.min);
    const maximum = Number(field.constraints.max);
    if (Number.isFinite(minimum)) schema.minimum = minimum;
    if (Number.isFinite(maximum)) schema.maximum = maximum;
    const stepRule = numericStepRule(field);
    if (!stepRule.any) schema.multipleOf = stepRule.step;
    return schema;
  }
  const schema = { type: 'string', title };
  if (field.required || field.constraints.min_length !== undefined) {
    schema.minLength = Math.max(field.required ? 1 : 0, field.constraints.min_length ?? 0);
  }
  if (field.constraints.max_length !== undefined) schema.maxLength = field.constraints.max_length;
  const patterns = [];
  if (field.kind === 'input') patterns.push('^[^\\r\\n]*$');
  if (field.html_type === 'email') {
    const emailSource = HTML_EMAIL.source.slice(1, -1);
    const valueSource = field.constraints.multiple
      ? `\\s*${emailSource}\\s*(?:,\\s*${emailSource}\\s*)*`
      : emailSource;
    patterns.push(field.required ? `^(?:${valueSource})$` : `^(?:$|${valueSource})$`);
  }
  if (field.html_type === 'url') {
    const uriAlternatives = [
      { pattern: NETWORK_URI_PATTERN },
      {
        allOf: [
          { pattern: ABSOLUTE_URI_PATTERN },
          { not: { pattern: NETWORK_SCHEME_PREFIX_PATTERN } }
        ]
      }
    ];
    schema.anyOf = field.required ? uriAlternatives : [{ const: '' }, ...uriAlternatives];
  }
  if (field.html_type === 'color') {
    patterns.length = 0;
    patterns.push('^#[0-9A-Fa-f]{6}$');
  }
  if (patterns.length === 1) schema.pattern = patterns[0];
  else if (patterns.length > 1) schema.allOf = patterns.map((pattern) => ({ pattern }));
  return schema;
}

function nodeTextEvidence(node, cache, { excludeControls = false } = {}) {
  let entry = cache.get(node);
  if (!entry) {
    entry = {};
    cache.set(node, entry);
  }
  const key = excludeControls ? 'without_controls' : 'all_text';
  if (!entry[key]) {
    const text = textEvidence(reviewTextContent(node, { excludeControls }));
    entry[key] = Object.freeze({
      ...text,
      semantics_digest: `sha256:${digest({
        text_digest: text.semantics_digest,
        tree_digest: semanticTreeDigest(node, { excludeControls })
      })}`
    });
  }
  return entry[key];
}

function labelEvidenceFor(control, {
  labelsByFor,
  elementsById,
  textEvidenceCache
}, {
  includeNativeLabels = true,
  includeOwnText = false,
  fallbacks = []
} = {}) {
  const labelledBy = attribute(control, 'aria-labelledby');
  if (labelledBy !== null) {
    const referenced = labelledBy
      .split(/\s+/)
      .filter(Boolean)
      .map((id) => elementsById.get(id))
      .filter(Boolean)
      .map((node) => nodeTextEvidence(node, textEvidenceCache));
    const combined = combineTextEvidence(referenced, ' ');
    if (combined.present) return combined;
  }

  const ariaLabel = textEvidence(attribute(control, 'aria-label'));
  if (ariaLabel.present) return ariaLabel;

  const id = attribute(control, 'id');
  if (includeNativeLabels && id && labelsByFor.has(id)) {
    const combined = labelsByFor.get(id);
    if (combined.present) return combined;
  }
  if (includeNativeLabels) {
    const wrapping = nearestAncestor(control, 'label');
    if (wrapping) {
      const wrapped = nodeTextEvidence(wrapping, textEvidenceCache, { excludeControls: true });
      if (wrapped.present) return wrapped;
    }
  }

  if (includeOwnText) {
    const ownText = nodeTextEvidence(control, textEvidenceCache);
    if (ownText.present) return ownText;
  }
  for (const fallback of fallbacks) {
    const evidence = textEvidence(fallback);
    if (evidence.present) return evidence;
  }
  return textEvidence('');
}

function fieldsetGroupEvidence(control, textEvidenceCache) {
  const fieldset = nearestAncestor(control, 'fieldset');
  const legend = fieldset ? firstLegend(fieldset) : null;
  return legend
    ? nodeTextEvidence(legend, textEvidenceCache, { excludeControls: true })
    : textEvidence('');
}

function ownerFor(node, formsByHtmlId) {
  if (hasAttribute(node, 'form')) return formsByHtmlId.get(attribute(node, 'form')) ?? null;
  return nearestAncestor(node, 'form');
}

function safePublicTarget(url) {
  const target = new URL(url);
  return {
    origin: target.origin,
    path: target.pathname,
    query_parameter_names: [...new Set([...target.searchParams.keys()])],
    has_fragment: Boolean(target.hash)
  };
}

function effectiveAction(form, submitter, documentUrl, baseUrl) {
  const override = submitter && hasAttribute(submitter, 'formaction') ? attribute(submitter, 'formaction') : null;
  const formAction = attribute(form, 'action');
  const raw = override !== null ? override : formAction;
  if (raw === null || raw.trim() === '') return new URL(documentUrl).href;
  return new URL(raw, baseUrl).href;
}

function effectiveMethod(form, submitter) {
  const override = submitter && hasAttribute(submitter, 'formmethod') ? attribute(submitter, 'formmethod') : null;
  return normalizeMethod(override ?? attribute(form, 'method'));
}

function effectiveEnctype(form, submitter) {
  const override = submitter && hasAttribute(submitter, 'formenctype') ? attribute(submitter, 'formenctype') : null;
  return normalizeEnctype(override ?? attribute(form, 'enctype'));
}

function hasNonUtf8AcceptCharset(form) {
  const value = attribute(form, 'accept-charset');
  if (!value) return false;
  return value.split(/[\s,]+/).filter(Boolean).some((item) => !['utf-8', 'utf8'].includes(item.toLowerCase()));
}

function fieldId(formId, sequence) {
  return `field_${digest(`${formId}\0ordinal:${sequence}`, 20)}`;
}

function optionId(id, occurrence) {
  return `option_${digest(`${id}\0ordinal:${occurrence}`, 18)}`;
}

function actionId(formId, sequence) {
  return `action_${digest(`${formId}\0ordinal:${sequence}`, 20)}`;
}

function formIdentity(form, index, duplicateIndex) {
  const htmlId = attribute(form, 'id');
  const stablePart = htmlId ? `html-id:${htmlId}:${duplicateIndex}` : `ordinal:${index}`;
  return {
    stable_part: stablePart,
    // Public IDs are contract-scoped ordinals. They must not become an
    // offline oracle for a capability-bearing source path or form value.
    id: `form_${digest(`ordinal:${index}`, 20)}`
  };
}

function makeSubmissionError(code, message, details) {
  const refusalCode = ['FORM_ACTION_NOT_FOUND', 'FORM_BINDING_NOT_FOUND'].includes(code)
    ? BRIDGE_REFUSAL_CODES.FORM_NOT_FOUND
    : code === 'UNSUPPORTED_FORM_ACTION'
      ? BRIDGE_REFUSAL_CODES.FORM_SEMANTICS_UNSUPPORTED
      : BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA;
  return new BridgeError(refusalCode, {
    detail: message,
    stage: 'form-compilation',
    ...(details === undefined ? {} : { requiredAction: { compiler_code: code, ...details } })
  });
}

function publicField(bindingField) {
  const { pattern: _withheldPattern, ...publicConstraints } = bindingField.constraints;
  const result = {
    field_id: bindingField.field_id,
    wire_name: bindingField.wire_name,
    label: bindingField.label,
    ...(bindingField.group_label ? { group_label: bindingField.group_label } : {}),
    kind: bindingField.kind,
    html_type: bindingField.html_type,
    order: bindingField.order,
    required: bindingField.required,
    agent_input_required: true,
    constraints: {
      ...publicConstraints,
      ...(bindingField.constraints.pattern === undefined ? {} : { pattern_present: true })
    },
    schema: null,
    source: bindingField.source,
    default_present: bindingField.default_value !== undefined && bindingField.default_value !== null
  };
  if (bindingField.options) {
    result.options = bindingField.options.map((option) => ({
      option_id: option.option_id,
      label: option.label,
      ...(option.group_label ? { group_label: option.group_label } : {}),
      disabled: option.disabled,
      ...(option.placeholder ? { placeholder: true } : {})
    }));
  }
  if (bindingField.secret) result.secret = true;
  result.schema = schemaForField(bindingField);
  return result;
}

function createInputSchema(fields) {
  // Explicit agent intent is separate from HTML constraint validation. Every
  // editable control must be supplied so no invisible HTML default can enter
  // an approved request.
  const required = fields.map((field) => field.field_id);
  return {
    type: 'object',
    additionalProperties: false,
    ...(required.length ? { required } : {}),
    properties: Object.fromEntries(fields.map((field) => [field.field_id, field.schema]))
  };
}

function optionBelongsToSelect(option, select) {
  let optgroupCount = 0;
  for (let ancestor = parentElement(option); ancestor; ancestor = parentElement(ancestor)) {
    if (ancestor === select) return true;
    if (['select', 'datalist', 'hr', 'option'].includes(ancestor.tagName)) return false;
    if (ancestor.tagName === 'optgroup' && ++optgroupCount > 1) return false;
  }
  return false;
}

function descendantOptions(select) {
  return [...walkElements(select)].filter((node) => node.tagName === 'option' && optionBelongsToSelect(node, select));
}

function collectOptionText(option) {
  const chunks = [];
  const stack = [...(option?.childNodes ?? [])].reverse();
  while (stack.length) {
    const node = stack.pop();
    if (node?.nodeName === '#text') {
      chunks.push(node.value ?? '');
      continue;
    }
    if (node?.tagName === 'script') continue;
    const children = node?.childNodes ?? [];
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
  return stripAndCollapseAsciiWhitespace(chunks.join(''));
}

function resolveBaseUrl(elements, documentUrl, findings, policies) {
  const base = elements.find((node) => node.tagName === 'base' && attribute(node, 'href') !== null);
  if (!base) return documentUrl;
  try {
    const candidate = new URL(attribute(base, 'href'), documentUrl).href;
    if (!cspAllowsDirectiveUrl('base-uri', candidate, documentUrl, policies)) {
      findings.push(finding('CSP_BASE_URI_IGNORED', 'Content Security Policy rejects the HTML base URL; relative form actions are resolved against the document URL.', {
        scope: 'document', blocking: false, node: base
      }));
      return documentUrl;
    }
    return candidate;
  } catch {
    findings.push(finding('INVALID_BASE_URL', 'The first HTML base element has an invalid URL and is ignored when resolving relative form actions.', {
      scope: 'document', blocking: false, node: base
    }));
    return documentUrl;
  }
}

function cspPolicies(value) {
  if (value === undefined || value === null || value === '') return [];
  const values = Array.isArray(value) ? value : [value];
  if (values.some((item) => typeof item !== 'string')) {
    throw new TypeError('contentSecurityPolicy must be a string or an array of strings');
  }
  return values.flatMap((item) => item.split(',')).map((item) => item.trim()).filter(Boolean);
}

function metaCspPolicies(elements) {
  return elements
    .filter((node) => node.tagName === 'meta'
      && String(attribute(node, 'http-equiv') ?? '').trim().toLowerCase() === 'content-security-policy')
    .flatMap((node) => cspPolicies(attribute(node, 'content')));
}

function directiveSources(policy, directiveName) {
  for (const segment of policy.split(';')) {
    const tokens = segment.trim().split(/\s+/).filter(Boolean);
    if (tokens[0]?.toLowerCase() === directiveName) return tokens.slice(1);
  }
  return null;
}

function cspSourceMatches(token, targetUrl, sourceUrl) {
  const normalized = token.toLowerCase();
  const target = new URL(targetUrl);
  const source = new URL(sourceUrl);
  if (normalized === "'self'") return target.origin === source.origin;
  if (normalized === '*') return true;
  if (/^[a-z][a-z0-9+.-]*:$/.test(normalized)) return target.protocol === normalized;
  if (/^[a-z0-9.-]+(?::\d+)?$/i.test(token)) {
    return target.origin === source.origin && target.host.toLowerCase() === normalized;
  }
  if (!/^https?:\/\//i.test(token) || token.includes('*')) return false;
  try {
    const allowed = new URL(token);
    if (allowed.username || allowed.password || allowed.origin !== target.origin) return false;
    if (allowed.pathname === '/') return true;
    return allowed.pathname.endsWith('/')
      ? target.pathname.startsWith(allowed.pathname)
      : target.pathname === allowed.pathname;
  } catch {
    return false;
  }
}

function cspAllowsDirectiveUrl(directiveName, targetUrl, sourceUrl, policies) {
  return policies.every((policy) => {
    const sources = directiveSources(policy, directiveName);
    if (sources === null) return true;
    return sources.some((token) => cspSourceMatches(token, targetUrl, sourceUrl));
  });
}

function cspSandboxBlocksForms(policies) {
  return policies.some((policy) => {
    const tokens = directiveSources(policy, 'sandbox');
    if (tokens === null) return false;
    const flags = new Set(tokens.map((token) => token.toLowerCase()));
    // Without allow-same-origin the browser uses an opaque origin and a POST
    // serializes Origin: null. The bridge deliberately refuses instead of
    // sending source-origin credentials under different semantics.
    return !flags.has('allow-forms') || !flags.has('allow-same-origin');
  });
}

/**
 * Compile static HTML forms into a redacted public contract and a private,
 * session-bound execution description. Unsupported forms remain visible as
 * typed findings and never prevent independent forms from compiling.
 */
export function compileForms(source, { contentSecurityPolicy } = {}) {
  const inheritedFindings = [...(source?.findings ?? [])];
  const findings = [...inheritedFindings];
  const sourceUrl = source?.source_url;
  const emptyContract = {
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    profile: HTTP_BRIDGE_PROFILE,
    profile_version: HTTP_BRIDGE_PROFILE_VERSION,
    source: {
      url: sourceUrl ?? null,
      encoding: source?.encoding ?? null,
      source_fingerprint: source?.source_fingerprint ?? null,
      parse_errors: source?.parse_errors ?? []
    },
    forms: [],
    actions: [],
    findings,
    executable: false
  };
  const emptyBinding = {
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    profile: `${HTTP_BRIDGE_PROFILE}-private-binding`,
    profile_version: HTTP_BRIDGE_PROFILE_VERSION,
    source_url: sourceUrl ?? null,
    source_fingerprint: source?.source_fingerprint ?? null,
    forms: {},
    actions: {}
  };

  if (!source?.document || !sourceUrl) {
    if (!findings.some((item) => item.blocking)) {
      findings.push(finding('HTML_SOURCE_NOT_EXECUTABLE', 'No parsed HTML document is available for form compilation.', { scope: 'document' }));
    }
    return { contract: emptyContract, execution_binding: emptyBinding, binding: emptyBinding, findings };
  }

  const elements = [...walkElements(source.document)];
  if (elements.length > MAX_INFERENCE_ELEMENTS) {
    findings.push(finding('HTML_ELEMENT_LIMIT_EXCEEDED', `The document exceeds the ${MAX_INFERENCE_ELEMENTS}-element inference limit.`, {
      scope: 'document'
    }));
    emptyContract.findings = findings;
    return { contract: emptyContract, execution_binding: emptyBinding, binding: emptyBinding, findings };
  }
  const headerPolicies = cspPolicies(contentSecurityPolicy);
  const formActionPolicies = [...headerPolicies, ...metaCspPolicies(elements)];
  const order = new Map(elements.map((node, index) => [node, index]));
  const forms = elements.filter((node) => node.tagName === 'form');
  const scripts = elements.filter((node) => node.tagName === 'script' && isExecutableScript(node));
  if (!forms.length) {
    const custom = elements.find((node) => node.tagName.includes('-') || hasAttribute(node, 'is'));
    if (custom) {
      findings.push(finding('UNSUPPORTED_CUSTOM_ELEMENT', 'The page contains custom elements but no static HTML form contract.', {
        scope: 'document', node: custom
      }));
    }
    const dynamicEvidence = scripts[0] ?? elements.find(hasInlineHandler) ?? null;
    findings.push(finding(
      dynamicEvidence ? 'UNSUPPORTED_SCRIPT_ONLY_FORMS' : 'NO_HTML_FORMS',
      dynamicEvidence
        ? 'The page exposes no static HTML form; script-generated forms require a browser or a reviewed site adapter.'
        : 'The page contains no HTML form to compile.',
      { scope: 'document', node: dynamicEvidence }
    ));
    emptyContract.findings = findings;
    return { contract: emptyContract, execution_binding: emptyBinding, binding: emptyBinding, findings };
  }

  const baseUrl = resolveBaseUrl(elements, sourceUrl, findings, formActionPolicies);
  const formsByHtmlId = new Map();
  for (const form of forms) {
    const id = attribute(form, 'id');
    if (id && !formsByHtmlId.has(id)) formsByHtmlId.set(id, form);
  }
  const elementsById = new Map();
  for (const element of elements) {
    const id = attribute(element, 'id');
    if (id && !elementsById.has(id)) elementsById.set(id, element);
  }
  const textEvidenceCache = new WeakMap();
  const labelPartsByFor = new Map();
  for (const label of elements.filter((node) => node.tagName === 'label')) {
    const target = attribute(label, 'for');
    if (!target) continue;
    const evidence = nodeTextEvidence(label, textEvidenceCache, { excludeControls: true });
    if (!evidence.present) continue;
    const parts = labelPartsByFor.get(target) ?? [];
    parts.push(evidence);
    labelPartsByFor.set(target, parts);
  }
  const labelsByFor = new Map(
    [...labelPartsByFor].map(([target, parts]) => [target, combineTextEvidence(parts)])
  );
  const labelContext = { labelsByFor, elementsById, textEvidenceCache };

  const controlsByForm = new Map(forms.map((form) => [form, []]));
  for (const control of elements.filter((node) => FORM_CONTROLS.has(node.tagName))) {
    const owner = ownerFor(control, formsByHtmlId);
    if (owner && controlsByForm.has(owner)) controlsByForm.get(owner).push(control);
    else if (hasAttribute(control, 'form')) {
      findings.push(finding('FORM_OWNER_NOT_FOUND', 'A form-associated control references a form id that does not exist.', {
        scope: 'control', blocking: false, node: control
      }));
    }
  }
  const customByForm = new Map(forms.map((form) => [form, []]));
  const objectsByForm = new Map(forms.map((form) => [form, []]));
  const scriptsByForm = new Map(forms.map((form) => [form, []]));
  for (const script of scripts) {
    const owner = nearestAncestor(script, 'form');
    if (owner && scriptsByForm.has(owner)) scriptsByForm.get(owner).push(script);
  }
  // A decorative custom element inside a form is not evidence that it joins
  // the form data set. A custom element with a name/form association might be
  // form-associated through code, which static HTML cannot safely reproduce.
  for (const custom of elements.filter((node) => (node.tagName.includes('-') || hasAttribute(node, 'is'))
    && (hasAttribute(node, 'name') || hasAttribute(node, 'form') || hasAttribute(node, 'is')))) {
    const owner = ownerFor(custom, formsByHtmlId);
    if (owner && customByForm.has(owner)) customByForm.get(owner).push(custom);
  }
  for (const object of elements.filter((node) => node.tagName === 'object' && attribute(node, 'name'))) {
    const owner = ownerFor(object, formsByHtmlId);
    if (owner && objectsByForm.has(owner)) objectsByForm.get(owner).push(object);
  }

  const publicForms = [];
  const publicActions = [];
  const binding = { ...emptyBinding, forms: {}, actions: {} };
  const duplicateIds = new Map();

  for (let formIndex = 0; formIndex < forms.length; formIndex += 1) {
    const form = forms[formIndex];
    const htmlId = attribute(form, 'id');
    const duplicateIndex = htmlId ? duplicateIds.get(htmlId) ?? 0 : 0;
    if (htmlId) duplicateIds.set(htmlId, duplicateIndex + 1);
    const identity = formIdentity(form, formIndex, duplicateIndex);
    const formId = identity.id;
    const formFindings = [];
    const formBlockers = [];
    const associatedControls = controlsByForm.get(form).sort((left, right) => order.get(left) - order.get(right));
    const formScripts = scriptsByForm.get(form);
    const associatedOrder = new Map(associatedControls.map((control, index) => [control, index]));
    const submitButtonElementCount = associatedControls.filter(isSubmitButtonElement).length;
    const implicitBlockerCount = associatedControls.filter((control) => control.tagName === 'input'
      && IMPLICIT_SUBMISSION_BLOCKERS.has(normalizeInputType(control))).length;
    const fields = [];
    const bodyPlan = [];
    const submitters = [];
    const managedStructure = [];
    const managedInstance = [];
    const unnamedValidatableControls = [];
    const occurrence = new Map();
    let fieldSequence = 0;
    const radioGroups = new Map();
    let unsupportedSubmitterCount = 0;
    let nonSubmittingActionControlCount = 0;

    const pushFormFinding = (item, { blocksForm = item.blocking } = {}) => {
      formFindings.push(item);
      findings.push(item);
      if (blocksForm) formBlockers.push(item);
    };
    const nextFieldId = (key) => {
      const current = occurrence.get(key) ?? 0;
      occurrence.set(key, current + 1);
      const id = fieldId(formId, fieldSequence);
      fieldSequence += 1;
      return id;
    };

    if (hasNonUtf8AcceptCharset(form)) {
      pushFormFinding(finding('UNSUPPORTED_NON_UTF8_FORM', 'The form requests a non-UTF-8 submission encoding.', {
        formId, node: form
      }));
    }
    for (const custom of customByForm.get(form)) {
      pushFormFinding(finding('UNSUPPORTED_CUSTOM_ELEMENT', 'A custom element may participate in form submission only after script execution, so this form is not inferred.', {
        scope: 'control', formId, node: custom,
        details: { tag_name: custom.tagName }
      }));
    }
    for (const object of objectsByForm.get(form)) {
      pushFormFinding(finding('UNSUPPORTED_OBJECT_CONTROL', 'A named object element can contribute browser or plugin-defined form data, so this form is not inferred.', {
        scope: 'control', formId, node: object
      }));
    }
    if (!associatedControls.length && formScripts.length) {
      pushFormFinding(finding('UNSUPPORTED_SCRIPT_ONLY_FORMS', 'This form has no static native controls and appears to depend on script-generated fields.', {
        formId, node: form
      }));
    }
    if (hasInlineHandler(form) || associatedControls.some(hasInlineHandler)) {
      pushFormFinding(finding('UNSUPPORTED_INLINE_FORM_SCRIPT', 'Inline script participates in this form workflow, so a wire-only submission could omit required behavior.', {
        formId, node: hasInlineHandler(form) ? form : associatedControls.find(hasInlineHandler)
      }));
    } else if (formScripts.length) {
      pushFormFinding(finding('FORM_SCRIPT_NOT_EXECUTED', 'Scripts inside this form are inert during inference; only the static HTML contract was compiled.', {
        formId, node: formScripts[0], blocking: false
      }), { blocksForm: false });
    } else if (scripts.length) {
      pushFormFinding(finding('PAGE_SCRIPT_NOT_EXECUTED', 'Page scripts may attach form listeners, but the bridge compiled only the standard static HTML request.', {
        formId, node: scripts[0], blocking: false
      }), { blocksForm: false });
    }

    for (const control of associatedControls) {
      if (isDisabled(control)) continue;
      const nodeOrder = associatedOrder.get(control);
      const wireName = attribute(control, 'name');

      if (hasAttribute(control, 'dirname')) {
        pushFormFinding(finding('UNSUPPORTED_DIRECTIONAL_FIELD', 'The dirname form feature depends on text direction and is not inferred without rendering.', {
          scope: 'control', formId, node: control
        }));
      }

      if (control.tagName === 'button') {
        if (normalizeButtonType(control) === 'submit') submitters.push({ node: control, order: nodeOrder, kind: 'button' });
        else if (normalizeButtonType(control) === 'button') nonSubmittingActionControlCount += 1;
        continue;
      }

      if (control.tagName === 'input' && hasAttribute(control, 'pattern')) {
        pushFormFinding(finding('UNSUPPORTED_PATTERN_VALIDATION', 'HTML pattern validation is not executed in-process because an untrusted regular expression can block the agent runtime.', {
          scope: 'control', formId, node: control
        }));
      }

      if (control.tagName === 'input') {
        const type = normalizeInputType(control);
        const readonlyApplies = hasAttribute(control, 'readonly')
          && TEXT_INPUT_TYPES.has(type)
          && !['range', 'color'].includes(type);
        if (type === 'file') {
          pushFormFinding(finding('UNSUPPORTED_FILE_CONTROL', 'File controls require an authorized artifact handle and multipart support; this form is refused.', {
            scope: 'control', formId, node: control
          }));
          continue;
        }
        if (type === 'image') {
          unsupportedSubmitterCount += 1;
          pushFormFinding(finding('UNSUPPORTED_IMAGE_SUBMITTER', 'Image submitters require click coordinates and are not compiled into an action.', {
            scope: 'control', formId, node: control, blocking: false
          }), { blocksForm: false });
          continue;
        }
        if (type === 'submit') {
          submitters.push({ node: control, order: nodeOrder, kind: 'input-submit' });
          continue;
        }
        if (NON_SUBMITTING_INPUT_TYPES.has(type)) {
          if (type === 'button') nonSubmittingActionControlCount += 1;
          continue;
        }
        if (UNSUPPORTED_TEMPORAL_INPUT_TYPES.has(type)) {
          pushFormFinding(finding('UNSUPPORTED_TEMPORAL_CONTROL', 'Temporal input sanitization and calendar step rules are not inferred by this draft bridge.', {
            scope: 'control', formId, node: control
          }));
          continue;
        }
        if (!wireName) {
          if (type !== 'hidden' && !readonlyApplies) unnamedValidatableControls.push(control);
          continue;
        }
        if (readonlyApplies && type === 'number') {
          pushFormFinding(finding('UNSUPPORTED_READONLY_TYPED_CONTROL', 'Readonly number value sanitization is not inferred by this draft bridge.', {
            scope: 'control', formId, node: control
          }));
          continue;
        }
        if (type === 'hidden' || readonlyApplies) {
          const rawValue = attribute(control, 'value') ?? '';
          const value = type === 'hidden' ? rawValue : readonlyInputValue(type, rawValue);
          const managed = {
            kind: 'managed',
            order: nodeOrder,
            wire_name: wireName,
            value,
            charset_marker: type === 'hidden' && wireName === '_charset_'
          };
          bodyPlan.push(managed);
          managedStructure.push({ order: nodeOrder, wire_name: wireName, kind: type === 'hidden' ? 'hidden' : 'readonly' });
          managedInstance.push({ order: nodeOrder, wire_name: wireName, value });
          continue;
        }

        if (type === 'radio') {
          if (!radioGroups.has(wireName)) radioGroups.set(wireName, []);
          radioGroups.get(wireName).push({ node: control, order: nodeOrder });
          continue;
        }

        const id = nextFieldId(`${wireName}\0input\0${type}`);
        const constraints = constraintsFor(control, type);
        if (type === 'range') {
          if (constraints.min === undefined) constraints.min = '0';
          if (constraints.max === undefined) constraints.max = '100';
        }
        const requiresExplicitDefault = ['range', 'color'].includes(type) && attribute(control, 'value') === null;
        if (requiresExplicitDefault) constraints.inference_requires_explicit_value = true;
        const label = labelEvidenceFor(control, labelContext, {
          fallbacks: [
            attribute(control, 'placeholder'),
            attribute(control, 'title'),
            attribute(control, 'name')
          ]
        });
        const groupLabel = fieldsetGroupEvidence(control, textEvidenceCache);
        const field = {
          field_id: id,
          wire_name: wireName,
          label: label.text,
          label_semantics_digest: label.semantics_digest,
          ...(groupLabel.present ? {
            group_label: groupLabel.text,
            group_label_semantics_digest: groupLabel.semantics_digest
          } : {}),
          kind: type === 'checkbox' ? 'checkbox' : 'input',
          html_type: type,
          order: nodeOrder,
          required: constraints.required || requiresExplicitDefault,
          constraints,
          source: nodeLocation(control),
          default_value: type === 'checkbox' ? hasAttribute(control, 'checked') : attribute(control, 'value') ?? '',
          ...(type === 'checkbox' ? { checked_value: attribute(control, 'value') ?? 'on' } : {}),
          ...(type === 'password' ? { secret: true } : {})
        };
        if (['number', 'range'].includes(type)) {
          const stepRule = numericStepRule(field);
          if (!stepRule.any && !stepBaseAlignedToZero(stepRule)) {
            pushFormFinding(finding('UNSUPPORTED_NUMERIC_STEP_BASE', 'This numeric control uses a non-zero step offset that cannot be represented faithfully by the public JSON Schema.', {
              scope: 'control', formId, fieldId: id, node: control
            }));
          }
        }
        fields.push(field);
        bodyPlan.push({ kind: type === 'checkbox' ? 'checkbox' : 'field', order: nodeOrder, field_id: id });
        continue;
      }

      if (!wireName) {
        if (control.tagName === 'select' || (control.tagName === 'textarea' && !hasAttribute(control, 'readonly'))) {
          unnamedValidatableControls.push(control);
        }
        continue;
      }
      if (control.tagName === 'textarea') {
        if (String(attribute(control, 'wrap') ?? '').toLowerCase() === 'hard') {
          pushFormFinding(finding('UNSUPPORTED_HARD_WRAPPED_TEXTAREA', 'A hard-wrapped textarea inserts user-agent line breaks that this draft bridge does not reproduce.', {
            scope: 'control', formId, node: control
          }));
          continue;
        }
        if (hasAttribute(control, 'readonly')) {
          const value = textContent(control);
          bodyPlan.push({ kind: 'managed', order: nodeOrder, wire_name: wireName, value });
          managedStructure.push({ order: nodeOrder, wire_name: wireName, kind: 'readonly-textarea' });
          managedInstance.push({ order: nodeOrder, wire_name: wireName, value });
          continue;
        }
        const id = nextFieldId(`${wireName}\0textarea`);
        const constraints = constraintsFor(control, 'textarea');
        const label = labelEvidenceFor(control, labelContext, {
          fallbacks: [
            attribute(control, 'placeholder'),
            attribute(control, 'title'),
            attribute(control, 'name')
          ]
        });
        const groupLabel = fieldsetGroupEvidence(control, textEvidenceCache);
        fields.push({
          field_id: id,
          wire_name: wireName,
          label: label.text,
          label_semantics_digest: label.semantics_digest,
          ...(groupLabel.present ? {
            group_label: groupLabel.text,
            group_label_semantics_digest: groupLabel.semantics_digest
          } : {}),
          kind: 'textarea',
          html_type: 'textarea',
          order: nodeOrder,
          required: constraints.required,
          constraints,
          source: nodeLocation(control),
          default_value: textContent(control)
        });
        bodyPlan.push({ kind: 'field', order: nodeOrder, field_id: id, normalize_newlines: true });
        continue;
      }

      if (control.tagName === 'select') {
        const id = nextFieldId(`${wireName}\0select\0${hasAttribute(control, 'multiple') ? 'multiple' : 'one'}`);
        const optionNodes = descendantOptions(control);
        const multiple = hasAttribute(control, 'multiple');
        const displaySize = numericAttribute(control, 'size', { integer: true, minimum: 0 });
        const required = hasAttribute(control, 'required');
        const options = optionNodes.map((option, index) => {
          const optionText = collectOptionText(option);
          const rawValue = attribute(option, 'value') ?? optionText;
          const group = nearestAncestor(option, 'optgroup');
          const labelAttribute = attribute(option, 'label');
          const optionLabel = textEvidence(labelAttribute !== null && labelAttribute !== '' ? labelAttribute : optionText);
          const groupLabel = textEvidence(group ? attribute(group, 'label') : '');
          return {
            option_id: optionId(id, index),
            raw_value: rawValue,
            label: optionLabel.text,
            label_semantics_digest: optionLabel.semantics_digest,
            ...(groupLabel.present ? {
              group_label: groupLabel.text,
              group_label_semantics_digest: groupLabel.semantics_digest
            } : {}),
            disabled: optionDisabled(option),
            selected: hasAttribute(option, 'selected'),
            placeholder: required && !multiple && (displaySize === null || displaySize <= 1)
              && index === 0 && parentElement(option) === control && rawValue === '',
            order: index
          };
        });
        const explicitlySelected = options.filter((option) => option.selected);
        const selected = explicitlySelected.filter((option) => !option.disabled);
        let defaultValue;
        if (multiple) defaultValue = selected.map((option) => option.option_id);
        else if (explicitlySelected.length) {
          const lastSelected = explicitlySelected.at(-1);
          defaultValue = lastSelected.disabled ? null : lastSelected.option_id;
        } else defaultValue = options.find((option) => !option.disabled)?.option_id ?? null;
        const constraints = constraintsFor(control, 'select');
        const label = labelEvidenceFor(control, labelContext, {
          fallbacks: [attribute(control, 'title'), attribute(control, 'name')]
        });
        const fieldsetLabel = fieldsetGroupEvidence(control, textEvidenceCache);
        fields.push({
          field_id: id,
          wire_name: wireName,
          label: label.text,
          label_semantics_digest: label.semantics_digest,
          ...(fieldsetLabel.present ? {
            group_label: fieldsetLabel.text,
            group_label_semantics_digest: fieldsetLabel.semantics_digest
          } : {}),
          kind: multiple ? 'select-multiple' : 'select-one',
          html_type: 'select',
          order: nodeOrder,
          required: constraints.required,
          constraints,
          source: nodeLocation(control),
          default_value: defaultValue,
          options
        });
        bodyPlan.push({ kind: multiple ? 'select-multiple' : 'select-one', order: nodeOrder, field_id: id });
      }
    }

    for (const [wireName, radios] of radioGroups) {
      const id = nextFieldId(`${wireName}\0radio-group`);
      const options = radios.map(({ node, order: radioOrder }, index) => {
        const rawValue = attribute(node, 'value') ?? 'on';
        const label = labelEvidenceFor(node, labelContext, {
          fallbacks: [attribute(node, 'title'), attribute(node, 'name')]
        });
        const groupLabel = fieldsetGroupEvidence(node, textEvidenceCache);
        return {
          option_id: optionId(id, index),
          raw_value: rawValue,
          label: label.text,
          label_semantics_digest: label.semantics_digest,
          ...(groupLabel.present ? {
            group_label: groupLabel.text,
            group_label_semantics_digest: groupLabel.semantics_digest
          } : {}),
          disabled: false,
          selected: hasAttribute(node, 'checked'),
          order: radioOrder,
          source: nodeLocation(node)
        };
      });
      const defaults = options.filter((option) => option.selected);
      const constraints = {
        required: radios.some(({ node }) => hasAttribute(node, 'required')),
        html_type: 'radio'
      };
      const groupLabels = [...new Map(options
        .filter((option) => option.group_label_semantics_digest)
        .map((option) => [option.group_label_semantics_digest, {
          text: option.group_label,
          semantics_digest: option.group_label_semantics_digest,
          present: true
        }])).values()];
      const groupLabel = combineTextEvidence(groupLabels);
      const optionLabels = combineTextEvidence(options.map((option) => ({
        text: option.label,
        semantics_digest: option.label_semantics_digest,
        present: Boolean(option.label)
      })));
      const fieldLabel = groupLabel.present ? groupLabel : optionLabels.present ? optionLabels : textEvidence(wireName);
      fields.push({
        field_id: id,
        wire_name: wireName,
        label: fieldLabel.text,
        label_semantics_digest: fieldLabel.semantics_digest,
        ...(groupLabel.present ? {
          group_label: groupLabel.text,
          group_label_semantics_digest: groupLabel.semantics_digest
        } : {}),
        kind: 'radio',
        html_type: 'radio',
        order: Math.min(...radios.map((radio) => radio.order)),
        required: constraints.required,
        constraints,
        source: nodeLocation(radios[0].node),
        default_value: defaults.at(-1)?.option_id ?? null,
        options
      });
      for (const option of options) {
        bodyPlan.push({ kind: 'radio-option', order: option.order, field_id: id, option_id: option.option_id });
      }
      if (defaults.length > 1) {
        pushFormFinding(finding('AMBIGUOUS_RADIO_DEFAULT', 'Multiple radio controls in one group are marked checked; the last source value is used as the default.', {
          scope: 'field', blocking: false, formId, fieldId: id, node: radios.at(-1).node
        }), { blocksForm: false });
      }
    }

    fields.sort((left, right) => left.order - right.order);
    bodyPlan.sort((left, right) => left.order - right.order);
    const publicFields = fields.map(publicField);
    const inputSchema = createInputSchema(publicFields);
    if (!submitters.length && nonSubmittingActionControlCount) {
      pushFormFinding(finding('UNSUPPORTED_SCRIPT_ONLY_FORM_ACTION', 'The form exposes only non-submitting button controls; they do not define a standard HTML form submission contract.', {
        formId, node: form
      }));
    }
    if (!submitButtonElementCount && implicitBlockerCount > 1) {
      pushFormFinding(finding('UNSUPPORTED_IMPLICIT_SUBMISSION', 'A form with no submit button and more than one blocking input cannot be implicitly submitted under the standard HTML algorithm.', {
        formId, node: form
      }));
    }
    const candidates = submitters.length
      ? submitters
      : submitButtonElementCount || unsupportedSubmitterCount || nonSubmittingActionControlCount || implicitBlockerCount > 1
        ? []
        : [{ node: null, order: Number.MAX_SAFE_INTEGER, kind: 'implicit' }];
    const actionRecords = [];
    const sharedFormFindings = [...formFindings];

    for (let submitterIndex = 0; submitterIndex < candidates.length; submitterIndex += 1) {
      const submitter = candidates[submitterIndex];
      const submitterName = submitter.node ? attribute(submitter.node, 'name') : null;
      const submitterValue = submitter.node ? attribute(submitter.node, 'value') : null;
      const id = actionId(formId, submitterIndex);
      const actionFindings = [...sharedFormFindings];
      const actionSpecificStart = actionFindings.length;
      const validationBypassed = hasAttribute(form, 'novalidate') || Boolean(submitter.node && hasAttribute(submitter.node, 'formnovalidate'));
      let method = effectiveMethod(form, submitter.node);
      let enctype = effectiveEnctype(form, submitter.node);
      let targetUrl = null;

      try {
        targetUrl = effectiveAction(form, submitter.node, sourceUrl, baseUrl);
        const parsedTarget = new URL(targetUrl);
        if (!['http:', 'https:'].includes(parsedTarget.protocol)) {
          actionFindings.push(finding('UNSUPPORTED_ACTION_SCHEME', 'Form actions must use HTTP or HTTPS.', {
            scope: 'action', actionId: id, formId, node: submitter.node ?? form,
            details: { scheme: parsedTarget.protocol }
          }));
        }
        if (parsedTarget.username || parsedTarget.password) {
          actionFindings.push(finding('UNSUPPORTED_URL_CREDENTIALS', 'Credentials embedded in a form action URL are refused.', {
            scope: 'action', actionId: id, formId, node: submitter.node ?? form
          }));
        }
        if (parsedTarget.origin !== new URL(sourceUrl).origin) {
          actionFindings.push(finding('UNSUPPORTED_CROSS_ORIGIN_ACTION', 'Cross-origin form submission requires an explicit reviewed adapter and is not inferred.', {
            scope: 'action', actionId: id, formId, node: submitter.node ?? form,
            details: { source_origin: new URL(sourceUrl).origin, target_origin: parsedTarget.origin }
          }));
        }
        if (!cspAllowsDirectiveUrl('form-action', targetUrl, sourceUrl, formActionPolicies)) {
          actionFindings.push(finding('UNSUPPORTED_CSP_FORM_ACTION', 'Content Security Policy does not permit this form action, so the bridge will not bypass it.', {
            scope: 'action', actionId: id, formId, node: submitter.node ?? form,
            details: { policy_count: formActionPolicies.length }
          }));
        }
        // The CSP sandbox directive is not honored from a meta element, but a
        // A response-header sandbox must preserve both form submission and
        // same-origin semantics for this source-origin HTTP emulation.
        if (cspSandboxBlocksForms(headerPolicies)) {
          actionFindings.push(finding('UNSUPPORTED_CSP_SANDBOX', 'Content Security Policy sandbox flags do not preserve both form submission and same-origin semantics, so the bridge will not bypass that restriction.', {
            scope: 'action', actionId: id, formId, node: submitter.node ?? form,
            details: { policy_count: headerPolicies.length }
          }));
        }
      } catch {
        actionFindings.push(finding('INVALID_FORM_ACTION', 'The effective form action URL is invalid.', {
          scope: 'action', actionId: id, formId, node: submitter.node ?? form
        }));
      }

      if (method === 'dialog') {
        actionFindings.push(finding('UNSUPPORTED_DIALOG_METHOD', 'Forms using method=dialog do not produce an HTTP request and are not executable by this bridge.', {
          scope: 'action', actionId: id, formId, node: submitter.node ?? form
        }));
      }
      if (method === 'post' && enctype === 'multipart/form-data') {
        actionFindings.push(finding('UNSUPPORTED_MULTIPART_FORM', 'Multipart form submission is not implemented by this bridge profile.', {
          scope: 'action', actionId: id, formId, node: submitter.node ?? form
        }));
      }
      if (method === 'post' && enctype === 'text/plain') {
        actionFindings.push(finding('UNSUPPORTED_TEXT_PLAIN_FORM', 'text/plain form submission is not implemented by this bridge profile.', {
          scope: 'action', actionId: id, formId, node: submitter.node ?? form
        }));
      }
      if (submitter.kind === 'input-submit' && submitterName && submitterValue === null) {
        actionFindings.push(finding('AMBIGUOUS_SUBMITTER_VALUE', 'A named input submitter without an explicit value depends on user-agent defaults.', {
          scope: 'action', actionId: id, formId, node: submitter.node
        }));
      }
      if (!validationBypassed && unnamedValidatableControls.length) {
        actionFindings.push(finding('UNSUPPORTED_UNNAMED_VALIDATABLE_CONTROL', 'An enabled editable control without a name can block browser constraint validation but cannot be represented in the request contract.', {
          scope: 'action', actionId: id, formId, node: unnamedValidatableControls[0],
          details: { control_count: unnamedValidatableControls.length }
        }));
      }

      for (const item of actionFindings.slice(actionSpecificStart)) {
        formFindings.push(item);
        findings.push(item);
      }

      const executable = Boolean(targetUrl) && !actionFindings.some((item) => item.blocking);
      const submitterLabel = submitter.node
        ? labelEvidenceFor(submitter.node, labelContext, {
            includeOwnText: submitter.kind === 'button',
            fallbacks: [
              submitterValue,
              attribute(submitter.node, 'title'),
              attribute(submitter.node, 'name'),
              'Submit form'
            ]
          })
        : textEvidence('Submit form');
      const actionInputSchema = validationBypassed
        ? {
            type: inputSchema.type,
            additionalProperties: inputSchema.additionalProperties,
            properties: Object.fromEntries(Object.entries(inputSchema.properties).map(([fieldKey, schema]) => {
              const relaxed = { ...schema };
              for (const keyword of ['const', 'minLength', 'maxLength', 'minItems', 'minimum', 'maximum', 'multipleOf', 'format', 'anyOf']) delete relaxed[keyword];
              const publicField = publicFields.find((field) => field.field_id === fieldKey);
              if (['email', 'url'].includes(publicField?.html_type)) {
                delete relaxed.allOf;
                relaxed.pattern = '^[^\\r\\n]*$';
              }
              if (publicField?.kind === 'select-one') {
                relaxed.enum = publicField.options.filter((option) => !option.disabled).map((option) => option.option_id);
              }
              if (['radio', 'select-one'].includes(publicField?.kind) && !relaxed.enum.includes(null)) {
                relaxed.type = ['string', 'null'];
                relaxed.enum = [...relaxed.enum, null];
              }
              return [fieldKey, relaxed];
            })),
            required: inputSchema.required
          }
        : inputSchema;
      const publicAction = {
        action_id: id,
        form_id: formId,
        label: submitterLabel.text || 'Submit form',
        method: method.toUpperCase(),
        enctype: method === 'post' ? enctype : URL_ENCODED,
        target: targetUrl ? safePublicTarget(targetUrl) : null,
        input_schema: actionInputSchema,
        field_ids: publicFields.map((field) => field.field_id),
        submitter: submitter.node ? {
          kind: submitter.kind,
          named: Boolean(submitterName),
          source: nodeLocation(submitter.node)
        } : { kind: 'implicit', named: false, source: null },
        validation_bypassed: validationBypassed,
        derivation: executable ? 'html-derived' : 'unsupported',
        assurance: createAssuranceVector({
          input_completeness: executable
            ? scripts.length ? ASSURANCE_LEVELS.HEURISTIC : ASSURANCE_LEVELS.DIRECT
            : ASSURANCE_LEVELS.CONFLICTED,
          freshness: ASSURANCE_LEVELS.DIRECT
        }),
        managed_fields: {
          count: managedStructure.length,
          fingerprint: `sha256:${digest(managedStructure)}`
        },
        findings: actionFindings,
        executable
      };
      const actionBinding = {
        action_id: id,
        form_id: formId,
        method: method.toUpperCase(),
        enctype: method === 'post' ? enctype : URL_ENCODED,
        action_url: targetUrl,
        input_schema: actionInputSchema,
        validation_bypassed: validationBypassed,
        submitter_label_semantics_digest: submitterLabel.semantics_digest,
        submitter: submitter.node ? {
          order: submitter.order,
          wire_name: submitterName,
          value: submitterValue ?? (submitter.kind === 'button' ? '' : null)
        } : null,
        executable,
        fingerprint: `sha256:${digest({
          form_id: formId,
          method,
          enctype,
          target_url: targetUrl,
          submitter_name: submitterName,
          submitter_value: submitterValue,
          submitter_label_semantics_digest: submitterLabel.semantics_digest,
          input_schema: actionInputSchema,
          validation_bypassed: validationBypassed
        })}`
      };
      publicActions.push(publicAction);
      actionRecords.push(publicAction);
      binding.actions[id] = actionBinding;
    }

    if (!actionRecords.some((action) => action.executable)) {
      const item = finding('NO_EXECUTABLE_FORM_ACTION', 'No submitter variant for this form can be executed safely by the HTTP bridge.', {
        formId, node: form
      });
      formFindings.push(item);
      findings.push(item);
    }

    const formLabel = labelEvidenceFor(form, labelContext, {
      includeNativeLabels: false,
      fallbacks: [
        attribute(form, 'name'),
        attribute(form, 'id'),
        `Form ${formIndex + 1}`
      ]
    });
    const formSemanticText = nodeTextEvidence(form, textEvidenceCache);
    const structure = {
      form_identity: identity.stable_part,
      form_label: formLabel.text,
      form_label_semantics_digest: formLabel.semantics_digest,
      semantic_text_digest: formSemanticText.semantics_digest,
      fields: publicFields.map((field, fieldIndex) => ({
        field_id: field.field_id,
        wire_name: field.wire_name,
        label: field.label,
        label_semantics_digest: fields[fieldIndex].label_semantics_digest,
        ...(field.group_label ? {
          group_label: field.group_label,
          group_label_semantics_digest: fields[fieldIndex].group_label_semantics_digest
        } : {}),
        kind: field.kind,
        html_type: field.html_type,
        required: field.required,
        constraints: field.constraints,
        options: field.options?.map((option, optionIndex) => ({
          option_id: option.option_id,
          label: option.label,
          label_semantics_digest: fields[fieldIndex].options[optionIndex].label_semantics_digest,
          ...(option.group_label ? {
            group_label: option.group_label,
            group_label_semantics_digest: fields[fieldIndex].options[optionIndex].group_label_semantics_digest
          } : {}),
          disabled: option.disabled,
          placeholder: option.placeholder === true
        }))
      })),
      managed_structure: managedStructure,
      actions: actionRecords.map((action) => ({
        action_id: action.action_id,
        label: action.label,
        label_semantics_digest: binding.actions[action.action_id].submitter_label_semantics_digest,
        method: action.method,
        enctype: action.enctype,
        target: action.target,
        submitter: action.submitter.kind,
        validation_bypassed: action.validation_bypassed
      })),
      finding_codes: [...new Set(formFindings.map((item) => item.code))].sort()
    };
    const formFingerprint = `sha256:${digest(structure)}`;
    const publicForm = {
      form_id: formId,
      html_id: htmlId || null,
      label: formLabel.text,
      fingerprint: formFingerprint,
      source: nodeLocation(form),
      fields: publicFields,
      action_ids: actionRecords.map((action) => action.action_id),
      managed_fields: {
        count: managedStructure.length,
        fingerprint: `sha256:${digest(managedStructure)}`
      },
      findings: formFindings,
      executable: actionRecords.some((action) => action.executable)
    };
    publicForms.push(publicForm);
    binding.forms[formId] = {
      form_id: formId,
      fingerprint: formFingerprint,
      // Instance freshness binds the exact managed values and form structure,
      // not unrelated timestamps/ads elsewhere in the HTML response.
      instance_fingerprint: `sha256:${digest({ structure, managed_instance: managedInstance })}`,
      fields: Object.fromEntries(fields.map((field) => [field.field_id, field])),
      body_plan: bodyPlan,
      action_ids: actionRecords.map((action) => action.action_id)
    };
  }

  const contract = {
    protocol: HTTP_BRIDGE_PROTOCOL,
    protocol_version: HTTP_BRIDGE_PROTOCOL_VERSION,
    profile: HTTP_BRIDGE_PROFILE,
    profile_version: HTTP_BRIDGE_PROFILE_VERSION,
    source: {
      url: sourceUrl,
      base_url: safePublicTarget(baseUrl),
      encoding: source.encoding,
      source_fingerprint: source.source_fingerprint,
      parse_errors: source.parse_errors
    },
    contract_fingerprint: `sha256:${digest({
      source: safePublicTarget(sourceUrl),
      forms: publicForms.map((form) => ({ form_id: form.form_id, fingerprint: form.fingerprint })),
      actions: publicActions.map((action) => ({
        action_id: action.action_id,
        form_id: action.form_id,
        method: action.method,
        enctype: action.enctype,
        target: action.target,
        executable: action.executable
      }))
    })}`,
    forms: publicForms,
    actions: publicActions,
    findings,
    executable: publicActions.some((action) => action.executable)
  };
  binding.contract_fingerprint = contract.contract_fingerprint;

  return { contract, execution_binding: binding, binding, findings };
}

function valueForField(field, input) {
  if (Object.hasOwn(input, field.field_id)) return input[field.field_id];
  return field.default_value;
}

function validEmailValue(value, multiple) {
  const candidates = multiple ? value.split(',').map((item) => item.trim()) : [value];
  return candidates.length > 0 && candidates.every((item) => item !== '' && HTML_EMAIL.test(item));
}

function validAbsoluteUrl(value) {
  return NETWORK_URI.test(value)
    || (!NETWORK_SCHEME_PREFIX.test(value) && ABSOLUTE_URI.test(value));
}

function decimalFraction(value) {
  const match = String(value).match(/^([+-]?)(\d+)(?:\.(\d*))?(?:[eE]([+-]?\d+))?$/);
  if (!match) return null;
  const sign = match[1] === '-' ? -1n : 1n;
  const fractionLength = (match[3] ?? '').length;
  const exponent = Number(match[4] ?? 0) - fractionLength;
  let numerator = sign * BigInt(`${match[2]}${match[3] ?? ''}`);
  let denominator = 1n;
  if (exponent >= 0) numerator *= 10n ** BigInt(exponent);
  else denominator = 10n ** BigInt(-exponent);
  return { numerator, denominator };
}

function numericStepRule(field) {
  const rawStep = field.constraints.step;
  if (typeof rawStep === 'string' && rawStep.trim().toLowerCase() === 'any') {
    return { any: true, step: null, base: null };
  }
  const numericStep = rawStep === undefined ? 1 : Number(rawStep);
  const step = Number.isFinite(numericStep) && numericStep > 0 ? numericStep : 1;
  const numericMin = Number(field.constraints.min);
  const numericDefault = Number(field.default_value);
  const base = Number.isFinite(numericMin)
    ? field.constraints.min
    : field.default_value !== '' && Number.isFinite(numericDefault)
      ? field.default_value
      : 0;
  return { any: false, step, base };
}

function stepBaseAlignedToZero(rule) {
  const baseFraction = decimalFraction(rule.base);
  const stepFraction = decimalFraction(rule.step);
  if (!baseFraction || !stepFraction || stepFraction.numerator <= 0n) return false;
  const numerator = baseFraction.numerator * stepFraction.denominator;
  const denominator = baseFraction.denominator * stepFraction.numerator;
  return numerator % denominator === 0n;
}

function numberStepMismatch(value, field) {
  const rule = numericStepRule(field);
  if (rule.any) return false;
  const valueFraction = decimalFraction(value);
  const baseFraction = decimalFraction(rule.base);
  const stepFraction = decimalFraction(rule.step);
  if (!valueFraction || !baseFraction || !stepFraction || stepFraction.numerator <= 0n) return true;
  const differenceNumerator = (valueFraction.numerator * baseFraction.denominator)
    - (baseFraction.numerator * valueFraction.denominator);
  const quotientNumerator = differenceNumerator * stepFraction.denominator;
  const quotientDenominator = valueFraction.denominator * baseFraction.denominator * stepFraction.numerator;
  return quotientNumerator % quotientDenominator !== 0n;
}

function validateInput(action, form, input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw makeSubmissionError('INVALID_FORM_ARGUMENTS', 'Form action arguments must be a JSON object.');
  }
  const allowed = new Set(Object.keys(form.fields));
  for (const key of Object.keys(input)) {
    if (!allowed.has(key)) {
      throw makeSubmissionError('UNKNOWN_FORM_FIELD', 'Input contains a field ID that was not issued by this form contract.');
    }
  }
  if (!action.executable) throw makeSubmissionError('UNSUPPORTED_FORM_ACTION', `Form action is not executable: ${action.action_id}`, { action_id: action.action_id });
  const enforceConstraints = !action.validation_bypassed;
  for (const [id, field] of Object.entries(form.fields)) {
    if (!Object.hasOwn(input, id)) {
      throw makeSubmissionError('EXPLICIT_FORM_FIELD_REQUIRED', `Every editable form field needs an explicit agent value: ${id}`, { field_id: id });
    }
    const value = input[id];
    if (value === null && ['radio', 'select-one'].includes(field.kind)
        && (!enforceConstraints || !field.required)) continue;
    if (field.kind === 'checkbox' && typeof value !== 'boolean') {
      throw makeSubmissionError('INVALID_FORM_FIELD', `${id} must be a boolean.`, { field_id: id });
    }
    if (enforceConstraints && field.kind === 'checkbox' && field.required && value !== true) {
      throw makeSubmissionError('INVALID_FORM_FIELD', `${id} must be accepted.`, { field_id: id });
    }
    if ((field.kind === 'radio' || field.kind === 'select-one') && !field.options.some((option) => option.option_id === value && !option.disabled)) {
      throw makeSubmissionError('INVALID_FORM_OPTION', `${id} does not name an available option.`, { field_id: id });
    }
    if (enforceConstraints && field.kind === 'radio' && field.required) {
      const selected = field.options.find((option) => option.option_id === value && !option.disabled);
      if (!selected) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} requires an available option.`, { field_id: id });
      }
    }
    if (enforceConstraints && field.kind === 'select-one' && field.required) {
      const selected = field.options.find((option) => option.option_id === value && !option.disabled);
      if (!selected || selected.placeholder) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} requires a non-empty option.`, { field_id: id });
      }
    }
    if (field.kind === 'select-multiple') {
      if (!Array.isArray(value) || value.some((candidate) => !field.options.some((option) => option.option_id === candidate && !option.disabled))) {
        throw makeSubmissionError('INVALID_FORM_OPTION', `${id} must be an array of available option ids.`, { field_id: id });
      }
      if (new Set(value).size !== value.length) {
        throw makeSubmissionError('INVALID_FORM_OPTION', `${id} must not repeat an option id.`, { field_id: id });
      }
      if (enforceConstraints && field.required && value.length === 0) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} requires at least one option.`, { field_id: id });
      }
    }
    if (['number', 'range'].includes(field.html_type) && (typeof value !== 'number' || !Number.isFinite(value))) {
      throw makeSubmissionError('INVALID_FORM_FIELD', `${id} must be a number.`, { field_id: id });
    }
    if (!['checkbox', 'radio', 'select-one', 'select-multiple'].includes(field.kind)
        && !['number', 'range'].includes(field.html_type)
        && typeof value !== 'string') {
      throw makeSubmissionError('INVALID_FORM_FIELD', `${id} must be a string.`, { field_id: id });
    }
    if (typeof value === 'string') {
      if (field.kind === 'input' && /[\r\n]/.test(value)) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} must not contain a line break.`, { field_id: id });
      }
      if (field.html_type === 'color' && !/^#[0-9A-Fa-f]{6}$/.test(value)) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} is not a valid simple color.`, { field_id: id });
      }
      if (enforceConstraints && field.required && value === '') {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} must not be empty.`, { field_id: id });
      }
      if (enforceConstraints && field.constraints.min_length !== undefined && value.length < field.constraints.min_length) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} is shorter than its declared minimum length.`, { field_id: id });
      }
      if (enforceConstraints && field.constraints.max_length !== undefined && value.length > field.constraints.max_length) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} exceeds its declared maximum length.`, { field_id: id });
      }
      if (enforceConstraints && value !== '' && field.html_type === 'email'
          && !validEmailValue(value, field.constraints.multiple === true)) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} is not a valid email address.`, { field_id: id });
      }
      if (enforceConstraints && value !== '' && field.html_type === 'url' && !validAbsoluteUrl(value)) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} is not a valid absolute URL.`, { field_id: id });
      }
    }
    if (enforceConstraints && typeof value === 'number') {
      const minimum = Number(field.constraints.min);
      const maximum = Number(field.constraints.max);
      if (Number.isFinite(minimum) && value < minimum) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} is below its declared minimum.`, { field_id: id });
      }
      if (Number.isFinite(maximum) && value > maximum) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} exceeds its declared maximum.`, { field_id: id });
      }
      if (numberStepMismatch(value, field)) {
        throw makeSubmissionError('INVALID_FORM_FIELD', `${id} does not satisfy its declared step.`, { field_id: id });
      }
    }
  }
}

/**
 * Materialize the exact private HTTP request for a compiled action. The return
 * value may contain hidden values and must never be exposed as a public contract
 * or receipt without redaction.
 */
export function buildFormSubmission(executionBinding, actionIdValue, input = {}) {
  const action = executionBinding?.actions?.[actionIdValue];
  if (!action) throw makeSubmissionError('FORM_ACTION_NOT_FOUND', `Unknown compiled form action: ${actionIdValue}`, { action_id: actionIdValue });
  const form = executionBinding.forms?.[action.form_id];
  if (!form) throw makeSubmissionError('FORM_BINDING_NOT_FOUND', `Execution binding is missing form ${action.form_id}.`, { form_id: action.form_id });
  validateInput(action, form, input);

  const entries = [];
  const plan = [...form.body_plan];
  if (action.submitter?.wire_name) {
    plan.push({
      kind: 'submitter',
      order: action.submitter.order,
      wire_name: action.submitter.wire_name,
      value: action.submitter.value ?? ''
    });
  }
  plan.sort((left, right) => left.order - right.order);

  for (const entry of plan) {
    if (entry.kind === 'managed' || entry.kind === 'submitter') {
      entries.push([entry.wire_name, entry.charset_marker ? 'UTF-8' : normalizeNewlines(entry.value)]);
      continue;
    }
    const field = form.fields[entry.field_id];
    const value = valueForField(field, input);
    if (value === undefined || value === null) continue;
    if (entry.kind === 'checkbox') {
      if (value === true) entries.push([field.wire_name, normalizeNewlines(field.checked_value)]);
      continue;
    }
    if (entry.kind === 'radio-option') {
      if (value !== entry.option_id) continue;
      const option = field.options.find((candidate) => candidate.option_id === entry.option_id);
      if (option && !option.disabled) entries.push([field.wire_name, normalizeNewlines(option.raw_value)]);
      continue;
    }
    if (entry.kind === 'select-one') {
      const option = field.options.find((candidate) => candidate.option_id === value);
      if (option && !option.disabled) entries.push([field.wire_name, normalizeNewlines(option.raw_value)]);
      continue;
    }
    if (entry.kind === 'select-multiple') {
      const selected = new Set(value);
      for (const option of field.options) {
        if (selected.has(option.option_id) && !option.disabled) entries.push([field.wire_name, normalizeNewlines(option.raw_value)]);
      }
      continue;
    }
    entries.push([field.wire_name, entry.normalize_newlines ? normalizeNewlines(value) : normalizeNewlines(value)]);
  }

  const encoded = new URLSearchParams(entries).toString();
  if (action.method === 'GET') {
    const url = new URL(action.action_url);
    url.search = encoded;
    return {
      action_id: actionIdValue,
      method: 'GET',
      url: url.href,
      headers: { accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1' },
      body: null,
      private_entries: entries,
      action_fingerprint: action.fingerprint
    };
  }
  if (action.method === 'POST' && action.enctype === URL_ENCODED) {
    return {
      action_id: actionIdValue,
      method: 'POST',
      url: action.action_url,
      headers: {
        accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.1',
        'content-type': 'application/x-www-form-urlencoded;charset=UTF-8'
      },
      body: encoded,
      private_entries: entries,
      action_fingerprint: action.fingerprint
    };
  }
  throw makeSubmissionError('UNSUPPORTED_FORM_ACTION', 'Only GET and application/x-www-form-urlencoded POST actions are materialized.', {
    action_id: actionIdValue,
    method: action.method,
    enctype: action.enctype
  });
}

export const compileFormContract = compileForms;
export const compileFormSubmission = buildFormSubmission;
