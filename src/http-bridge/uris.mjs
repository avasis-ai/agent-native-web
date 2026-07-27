const REPOSITORY_SCHEMA_ROOT = 'https://raw.githubusercontent.com/avasis-ai/agent-native-web/main/schemas/http-form-bridge';

export const HTTP_BRIDGE_SCHEMAS = Object.freeze({
  inferredContract: `${REPOSITORY_SCHEMA_ROOT}/inferred-contract-0.1-draft.json`,
  requestPreview: `${REPOSITORY_SCHEMA_ROOT}/request-preview-0.1-draft.json`,
  attemptReceipt: `${REPOSITORY_SCHEMA_ROOT}/attempt-receipt-0.1-draft.json`,
  evidence: `${REPOSITORY_SCHEMA_ROOT}/evidence-0.1-draft.json`
});

export const HTTP_BRIDGE_PROBLEM_REGISTRY = `${REPOSITORY_SCHEMA_ROOT}/problems-0.1-draft.json`;

export function httpBridgeProblemType(code) {
  const slug = String(code).toLocaleLowerCase('en-US').replaceAll('_', '-');
  return `${HTTP_BRIDGE_PROBLEM_REGISTRY}?problem=${encodeURIComponent(slug)}`;
}
