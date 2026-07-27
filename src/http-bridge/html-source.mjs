import { createHash } from 'node:crypto';
import { parse } from 'parse5';

const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
const UTF8_ALIASES = new Set(['utf-8', 'utf8', 'unicode-1-1-utf-8']);
const ASCII_ALIASES = new Set(['us-ascii', 'ascii']);

function sourceFinding(code, message, {
  blocking = true,
  severity = blocking ? 'error' : 'warning',
  location = null,
  details
} = {}) {
  return {
    code,
    kind: blocking ? 'unsupported' : 'warning',
    scope: 'document',
    severity,
    blocking,
    message,
    ...(location ? { location } : {}),
    ...(details === undefined ? {} : { details })
  };
}

function compactLocation(location) {
  if (!location) return null;
  return {
    start_line: location.startLine,
    start_column: location.startCol,
    start_offset: location.startOffset,
    end_line: location.endLine,
    end_column: location.endCol,
    end_offset: location.endOffset
  };
}

function normalizeCharset(value) {
  if (!value) return null;
  return String(value).trim().replace(/^['"]|['"]$/g, '').toLowerCase();
}

function charsetFromContentType(contentType) {
  if (typeof contentType !== 'string') return null;
  const match = contentType.match(/(?:^|;)\s*charset\s*=\s*(?:"([^"]+)"|'([^']+)'|([^;\s]+))/i);
  return normalizeCharset(match?.[1] ?? match?.[2] ?? match?.[3]);
}

function charsetFromMeta(asciiPrefix) {
  const declarations = [];
  const prefixDocument = parse(asciiPrefix);
  const stack = [...(prefixDocument.childNodes ?? [])];
  while (stack.length) {
    const node = stack.pop();
    stack.push(...(node?.childNodes ?? []));
    if (node?.tagName !== 'meta') continue;
    const attrs = Object.fromEntries((node.attrs ?? []).map((item) => [item.name.toLowerCase(), item.value]));
    if (attrs.charset) {
      declarations.push(normalizeCharset(attrs.charset));
      continue;
    }
    if (attrs['http-equiv']?.toLowerCase() !== 'content-type' || !attrs.content) continue;
    const nested = attrs.content.match(/charset\s*=\s*([^;\s]+)/i);
    if (nested) declarations.push(normalizeCharset(nested[1]));
  }
  return declarations.filter(Boolean);
}

function isUtf8Compatible(charset) {
  return charset === null || UTF8_ALIASES.has(charset) || ASCII_ALIASES.has(charset);
}

function mediaType(contentType) {
  return String(contentType || 'text/html').split(';', 1)[0].trim().toLowerCase();
}

function normalizeInput(input, options) {
  if (input && typeof input === 'object' && !Buffer.isBuffer(input) && !(input instanceof Uint8Array) && 'body' in input) {
    return {
      body: input.body,
      url: input.url ?? options.url,
      contentType: input.contentType ?? input.content_type ?? options.contentType ?? options.content_type,
      maxBytes: input.maxBytes ?? input.max_bytes ?? options.maxBytes ?? options.max_bytes
    };
  }
  return {
    body: input,
    url: options.url,
    contentType: options.contentType ?? options.content_type,
    maxBytes: options.maxBytes ?? options.max_bytes
  };
}

/**
 * Parse an HTML response into an inert parse5 tree. This function never executes
 * script, loads subresources, applies CSS, or creates a browser DOM.
 */
export function parseHtmlSource(input, options = {}) {
  const normalized = normalizeInput(input, options);
  const contentType = normalized.contentType ?? 'text/html; charset=utf-8';
  const findings = [];
  const parseErrors = [];
  const byteLimit = normalized.maxBytes ?? DEFAULT_MAX_BYTES;
  let sourceUrl = null;

  try {
    sourceUrl = new URL(normalized.url).href;
  } catch {
    findings.push(sourceFinding('INVALID_SOURCE_URL', 'HTML inference requires an absolute HTTP or HTTPS source URL.'));
  }
  if (sourceUrl && !['http:', 'https:'].includes(new URL(sourceUrl).protocol)) {
    findings.push(sourceFinding('UNSUPPORTED_SOURCE_SCHEME', 'HTML inference supports only HTTP and HTTPS source URLs.'));
  }
  if (sourceUrl && (new URL(sourceUrl).username || new URL(sourceUrl).password)) {
    findings.push(sourceFinding('UNSUPPORTED_SOURCE_CREDENTIALS', 'HTML inference refuses source URLs containing embedded credentials.'));
  }

  const type = mediaType(contentType);
  if (type !== 'text/html') {
    findings.push(sourceFinding('UNSUPPORTED_CONTENT_TYPE', `HTTP form inference does not parse ${type || 'an unknown content type'}.`, {
      details: { content_type: type || null, supported: ['text/html'] }
    }));
  }

  let bytes;
  if (typeof normalized.body === 'string') bytes = Buffer.from(normalized.body, 'utf8');
  else if (Buffer.isBuffer(normalized.body)) bytes = normalized.body;
  else if (normalized.body instanceof Uint8Array) bytes = Buffer.from(normalized.body);
  else {
    bytes = Buffer.alloc(0);
    findings.push(sourceFinding('INVALID_HTML_SOURCE', 'HTML source must be a string, Buffer, or Uint8Array.'));
  }

  if (bytes.length > byteLimit) {
    findings.push(sourceFinding('HTML_SOURCE_TOO_LARGE', `HTML source exceeds the ${byteLimit}-byte inference limit.`, {
      details: { byte_size: bytes.length, maximum_byte_size: byteLimit }
    }));
  }

  const headerCharset = charsetFromContentType(contentType);
  const prefix = bytes.subarray(0, Math.min(bytes.length, 4096)).toString('latin1');
  const metaCharsets = charsetFromMeta(prefix);
  const declaredCharsets = [headerCharset, ...metaCharsets].filter(Boolean);
  const unsupportedCharsets = [...new Set(declaredCharsets.filter((value) => !isUtf8Compatible(value)))];
  if (unsupportedCharsets.length) {
    findings.push(sourceFinding('UNSUPPORTED_NON_UTF8', 'The document declares an encoding that this bridge deliberately refuses to reinterpret.', {
      details: { declared_charsets: unsupportedCharsets, supported_charsets: ['utf-8'] }
    }));
  }

  if (declaredCharsets.some((value) => ASCII_ALIASES.has(value))
      && bytes.some((byte) => byte > 0x7f)) {
    findings.push(sourceFinding('UNSUPPORTED_NON_UTF8', 'The document declares US-ASCII but contains non-ASCII bytes; the bridge refuses to guess a browser encoding.', {
      details: { declared_charsets: [...new Set(declaredCharsets.filter((value) => ASCII_ALIASES.has(value)))], supported_charsets: ['utf-8', '7-bit us-ascii'] }
    }));
  }

  if (bytes.length >= 2 && ((bytes[0] === 0xff && bytes[1] === 0xfe) || (bytes[0] === 0xfe && bytes[1] === 0xff))) {
    findings.push(sourceFinding('UNSUPPORTED_NON_UTF8', 'UTF-16 encoded HTML is not supported by the inert HTML bridge.', {
      details: { declared_charsets: ['utf-16-bom'], supported_charsets: ['utf-8'] }
    }));
  }

  let html = null;
  if (!findings.some((finding) => finding.blocking)) {
    try {
      html = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
    } catch {
      findings.push(sourceFinding('INVALID_UTF8', 'The HTML response is not valid UTF-8.'));
    }
  }

  let document = null;
  if (html !== null && !findings.some((finding) => finding.blocking)) {
    document = parse(html, {
      sourceCodeLocationInfo: true,
      onParseError(error) {
        parseErrors.push({
          code: error.code,
          location: compactLocation(error)
        });
      }
    });
  }

  return {
    kind: 'inert-html-source',
    source_url: sourceUrl,
    content_type: type,
    encoding: html === null ? null : 'utf-8',
    byte_size: bytes.length,
    source_fingerprint: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
    html,
    document,
    parse_errors: parseErrors,
    findings,
    executable: document !== null && !findings.some((finding) => finding.blocking)
  };
}

export function* walkElements(root) {
  if (!root) return;
  const stack = [...(root.childNodes ?? [])].reverse();
  while (stack.length) {
    const node = stack.pop();
    if (node?.tagName) yield node;
    const children = node?.childNodes ?? [];
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
}

export function attributes(node) {
  return Object.fromEntries((node?.attrs ?? []).map((attribute) => [attribute.name.toLowerCase(), attribute.value]));
}

export function attribute(node, name) {
  const normalized = String(name).toLowerCase();
  return node?.attrs?.find((candidate) => candidate.name.toLowerCase() === normalized)?.value ?? null;
}

export function hasAttribute(node, name) {
  const normalized = String(name).toLowerCase();
  return Boolean(node?.attrs?.some((candidate) => candidate.name.toLowerCase() === normalized));
}

export function nodeLocation(node) {
  return compactLocation(node?.sourceCodeLocation);
}

export function textContent(node, { excludeControls = false } = {}) {
  if (!node) return '';
  const chunks = [];
  const stack = [node];
  while (stack.length) {
    const current = stack.pop();
    if (current?.nodeName === '#text') {
      chunks.push(current.value ?? '');
      continue;
    }
    if (current?.tagName === 'script' || current?.tagName === 'style') continue;
    if (excludeControls && ['input', 'select', 'textarea', 'button'].includes(current?.tagName)) continue;
    const children = current?.childNodes ?? [];
    for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
  }
  return chunks.join('');
}
