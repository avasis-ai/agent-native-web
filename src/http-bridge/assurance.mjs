import { BRIDGE_REFUSAL_CODES, BridgeError } from './errors.mjs';

export const ASSURANCE_DIMENSIONS = Object.freeze([
  'origin_authenticity',
  'transport',
  'input_completeness',
  'semantic_effect',
  'auth_subject',
  'freshness',
  'retry_safety',
  'outcome_verifiability'
]);

export const ASSURANCE_LEVELS = Object.freeze({
  UNKNOWN: 'unknown',
  HEURISTIC: 'heuristic',
  DIRECT: 'direct',
  AUTHORITATIVE: 'authoritative',
  VERIFIED: 'verified',
  CONFLICTED: 'conflicted'
});

const DIMENSION_SET = new Set(ASSURANCE_DIMENSIONS);
const LEVEL_SET = new Set(Object.values(ASSURANCE_LEVELS));

function invalid(detail) {
  return new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, { detail, stage: 'assurance' });
}

function assertPlainObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw invalid(`${label} must be a plain object`);
  }
}

export function isAssuranceLevel(value) {
  return LEVEL_SET.has(value);
}

export function createAssuranceVector(input = {}) {
  assertPlainObject(input, 'assurance');
  for (const dimension of Object.keys(input)) {
    if (!DIMENSION_SET.has(dimension)) throw invalid(`Unknown assurance dimension: ${dimension}`);
  }
  return Object.freeze(Object.fromEntries(ASSURANCE_DIMENSIONS.map((dimension) => {
    const level = input[dimension] ?? ASSURANCE_LEVELS.UNKNOWN;
    if (!isAssuranceLevel(level)) throw invalid(`Invalid assurance level for ${dimension}: ${level}`);
    return [dimension, level];
  })));
}

export function assertAssuranceVector(value) {
  assertPlainObject(value, 'assurance');
  const keys = Object.keys(value);
  if (keys.length !== ASSURANCE_DIMENSIONS.length || ASSURANCE_DIMENSIONS.some((dimension) => !keys.includes(dimension))) {
    throw invalid(`assurance must define exactly: ${ASSURANCE_DIMENSIONS.join(', ')}`);
  }
  return createAssuranceVector(value);
}

function allowedLevels(rule, dimension) {
  const values = typeof rule === 'string' ? [rule] : rule;
  if (!Array.isArray(values) || values.length === 0 || values.some((level) => !isAssuranceLevel(level))) {
    throw invalid(`Assurance requirement for ${dimension} must contain valid allowed levels`);
  }
  return new Set(values);
}

/**
 * Assurance is intentionally not numeric. A direct HTML observation cannot
 * compensate for unknown business semantics, and an average would hide that
 * missing gate. Policies name the acceptable evidence states per dimension.
 */
export function evaluateAssurance(assurance, requirements = {}) {
  const vector = assertAssuranceVector(assurance);
  assertPlainObject(requirements, 'assurance requirements');
  const blockers = [];
  for (const [dimension, rule] of Object.entries(requirements)) {
    if (!DIMENSION_SET.has(dimension)) throw invalid(`Unknown assurance requirement dimension: ${dimension}`);
    const allowed = allowedLevels(rule, dimension);
    if (!allowed.has(vector[dimension])) {
      blockers.push(Object.freeze({
        dimension,
        observed: vector[dimension],
        allowed: Object.freeze([...allowed])
      }));
    }
  }
  return Object.freeze({ passed: blockers.length === 0, blockers: Object.freeze(blockers) });
}

export const READ_ASSURANCE_REQUIREMENTS = Object.freeze({
  origin_authenticity: Object.freeze([ASSURANCE_LEVELS.DIRECT, ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  transport: Object.freeze([ASSURANCE_LEVELS.DIRECT, ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  input_completeness: Object.freeze([ASSURANCE_LEVELS.DIRECT, ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  freshness: Object.freeze([ASSURANCE_LEVELS.DIRECT, ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED])
});

export const APPROVED_COMMIT_ASSURANCE_REQUIREMENTS = Object.freeze({
  origin_authenticity: Object.freeze([ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  transport: Object.freeze([ASSURANCE_LEVELS.DIRECT, ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  input_completeness: Object.freeze([ASSURANCE_LEVELS.DIRECT, ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  semantic_effect: Object.freeze([ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED]),
  auth_subject: Object.freeze([ASSURANCE_LEVELS.VERIFIED]),
  freshness: Object.freeze([ASSURANCE_LEVELS.VERIFIED]),
  outcome_verifiability: Object.freeze([ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED])
});

export const AUTONOMOUS_COMMIT_ASSURANCE_REQUIREMENTS = Object.freeze({
  ...APPROVED_COMMIT_ASSURANCE_REQUIREMENTS,
  retry_safety: Object.freeze([ASSURANCE_LEVELS.AUTHORITATIVE, ASSURANCE_LEVELS.VERIFIED])
});
