#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { randomBytes, randomUUID } from 'node:crypto';
import { AgentProtocolError, AgentWebClient, UnsupportedAgentSiteError } from './client.mjs';
import { HttpBridgeClient } from './http-bridge/client.mjs';
import { BRIDGE_REFUSAL_CODES, BridgeError } from './http-bridge/errors.mjs';
import {
  acquireBridgeSessionLock,
  assertApprovalMatchesSession,
  consumeBridgeApproval,
  loadBridgeSession,
  persistBridgeSession,
  readBridgeApproval,
  writeBridgeApproval
} from './http-bridge/cli-session-store.mjs';

// Only this CLI module can mark factory-produced attempt evidence for direct
// top-level output. Arbitrary required_action objects never bypass redaction.
const CLI_ATTEMPT_RECEIPT = Symbol('agentweb.cli.attempt-receipt');

function attachCliAttemptReceipt(error, receipt) {
  if (error && typeof error === 'object' && receipt?.kind === 'attempt_receipt') {
    Object.defineProperty(error, CLI_ATTEMPT_RECEIPT, { value: receipt });
  }
  return error;
}

function parse(argv) {
  const positionals = [];
  const flags = {};
  for (let index = 0; index < argv.length; index += 1) {
    const value = argv[index];
    if (!value.startsWith('--')) positionals.push(value);
    else {
      const [rawKey, inline] = value.slice(2).split('=', 2);
      if (inline !== undefined) flags[rawKey] = inline;
      else if (argv[index + 1] && !argv[index + 1].startsWith('--')) flags[rawKey] = argv[++index];
      else flags[rawKey] = true;
    }
  }
  return { positionals, flags };
}

function booleanSwitch(flags, name) {
  const value = flags[name];
  if (value === undefined) return false;
  if (value !== true) throw new Error(`--${name} is a presence-only flag and does not accept a value`);
  return true;
}

async function stdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

async function jsonArgument(value) {
  if (value === '-') return JSON.parse(await stdin());
  return JSON.parse(value);
}

function help() {
  return `agentweb — direct agent-native website automation (no browser)

Native-client flags:
  --base-url URL        Site origin (default AGENT_BASE_URL or http://127.0.0.1:4317)
  --token TOKEN         Bearer token (default AGENT_TOKEN)

Commands:
  bridge inspect URL [--session-file PATH] [--allow-private-network]
  bridge prepare URL --action ID --input - [--session-file PATH --approval-file PATH] [--allow-private-network]
  bridge submit URL --action ID --input - --session-file PATH --approval-file PATH \\
    --approval-binding-digest HMAC --allow-unverified-write [--allow-private-network]
  discover
  capabilities
  query [--text TEXT] [--colour VALUE] [--max-price-minor N] [--in-stock]
  products [--query TEXT]
  product ID
  state [--scope all|catalog|cart|orders]
  actions
  preview ACTION --args JSON|-
  commit PREVIEW_ID [--idempotency-key KEY] [--confirm]
  receipt RECEIPT_ID
  events [--since N]
  media describe ID
  media data ID
  media fetch ID --output FILE [--region NAME]
  media read-mark ID
  ask TEXT
  automate buy --query TEXT [--quantity N] [--checkout --address TEXT --yes]
`;
}

function print(value) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
}

function bridgeClient(url, flags, { digestKey, cookieJar } = {}) {
  const target = new URL(url);
  const allowPrivateNetworks = booleanSwitch(flags, 'allow-private-network');
  const explicitOrigins = typeof flags['allow-origin'] === 'string'
    ? flags['allow-origin'].split(',').map((value) => value.trim()).filter(Boolean)
    : [];
  if (allowPrivateNetworks && !explicitOrigins.includes(target.origin)) explicitOrigins.push(target.origin);
  return new HttpBridgeClient({
    ...(digestKey === undefined ? {} : { digestKey }),
    sessionOptions: {
      allowedOrigins: explicitOrigins,
      allowPrivateNetworks,
      ...(cookieJar === undefined ? {} : { cookieJar })
    }
  });
}

async function bridgeInput(flags) {
  if (flags.input !== '-') {
    throw new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, {
      detail: 'Bridge form values must use --input - so credentials do not enter shell history.',
      stage: 'cli'
    });
  }
  try {
    return await jsonArgument('-');
  } catch {
    throw new BridgeError(BRIDGE_REFUSAL_CODES.INVALID_BRIDGE_DATA, {
      detail: 'Bridge stdin must contain one valid JSON object; parser details were withheld because the input may contain credentials.',
      stage: 'cli'
    });
  }
}

async function runBridge(subcommand, url, flags) {
  if (!url) throw new Error(`bridge ${subcommand ?? ''} requires URL`.trim());
  const sessionPath = flags['session-file'];
  const approvalPath = flags['approval-file'];
  if (sessionPath !== undefined && typeof sessionPath !== 'string') throw new Error('--session-file requires a path');
  if (approvalPath !== undefined && typeof approvalPath !== 'string') throw new Error('--approval-file requires a path');
  if (approvalPath && !sessionPath) throw new Error('--approval-file requires --session-file');
  if (sessionPath && approvalPath && sessionPath === approvalPath) {
    throw new Error('--session-file and --approval-file must be different paths');
  }
  if (subcommand === 'submit' && (!sessionPath || !approvalPath)) {
    throw new Error('bridge submit requires separate --session-file and --approval-file paths');
  }

  let digestKey = randomBytes(32);
  let session;
  let approval;
  let releaseSessionLock;
  if (sessionPath) {
    releaseSessionLock = await acquireBridgeSessionLock(sessionPath);
  }
  let client;
  let result;
  let primaryError;
  try {
    if (sessionPath) {
      session = await loadBridgeSession(sessionPath, url, { allowCreate: subcommand !== 'submit' });
    }
    if (subcommand === 'submit') {
      approval = await readBridgeApproval(approvalPath);
      assertApprovalMatchesSession(approval, session, url, flags.action);
      digestKey = approval.digestKey;
    }
    client = bridgeClient(url, flags, { digestKey, cookieJar: session?.cookieJar });
    operation: {
      const contract = await client.inspect(url);
      if (subcommand === 'inspect') {
        if (sessionPath) session = await persistBridgeSession(sessionPath, session, client.session.cookieJar);
        result = contract;
        break operation;
      }
      if (!flags.action) throw new Error(`bridge ${subcommand} requires --action ID`);
      const input = await bridgeInput(flags);
      const preview = await client.prepare({ contractId: contract.contract_id, actionId: flags.action, input });
      if (subcommand === 'prepare') {
        if (sessionPath) session = await persistBridgeSession(sessionPath, session, client.session.cookieJar);
        let approvalRecord;
        if (approvalPath) {
          approvalRecord = await writeBridgeApproval(approvalPath, {
            session,
            url,
            actionId: flags.action,
            approvalBindingDigest: preview.approval_binding_digest,
            expiresAt: preview.expires_at,
            digestKey
          });
        }
        result = {
          contract,
          preview,
          session_state: sessionPath
            ? {
                path: sessionPath,
                session_id: session.record.session_id,
                generation: session.record.generation,
                expires_at: session.record.expires_at,
                contains_credentials: true
              }
            : { created: false },
          approval_capsule: approvalRecord
            ? { path: approvalPath, approval_id: approvalRecord.approval_id, expires_at: approvalRecord.expires_at, one_shot: true }
            : { created: false, dispatch_available: false }
        };
        break operation;
      }
      if (subcommand === 'submit') {
        if (!flags['approval-binding-digest']) {
          throw new BridgeError(BRIDGE_REFUSAL_CODES.APPROVAL_REQUIRED, {
            detail: 'bridge submit requires the approval_binding_digest returned by the matching bridge prepare run.',
            stage: 'cli',
            requiredAction: { kind: 'review_bridge_prepare_then_pass_approval_binding_digest' }
          });
        }
        if (flags['approval-binding-digest'] !== approval.record.approval_binding_digest
          || flags['approval-binding-digest'] !== preview.approval_binding_digest) {
          throw new BridgeError(BRIDGE_REFUSAL_CODES.APPROVAL_BINDING_MISMATCH, {
            detail: 'The approved binding does not match the restored session, form structure, assurance, and application request plan.',
            stage: 'cli'
          });
        }
        if (!booleanSwitch(flags, 'allow-unverified-write')) {
          throw new BridgeError(BRIDGE_REFUSAL_CODES.COMMIT_NOT_AUTOMATABLE, {
            detail: 'bridge submit requires --allow-unverified-write because generic HTML cannot prove the remote effect.',
            stage: 'cli'
          });
        }
        if (Date.parse(approval.record.expires_at) <= Date.now()) {
          throw new BridgeError(BRIDGE_REFUSAL_CODES.PREVIEW_STALE, {
            detail: 'The one-shot bridge approval expired before dispatch; prepare and approve a new request.',
            stage: 'cli'
          });
        }

        let receipt;
        let dispatchError;
        let sessionGenerationSpent = false;
        let approvalConsumed = false;
        try {
          receipt = await client.dispatch(preview.preview_id, {
            approvalDigest: preview.preview_digest,
            allowUnverifiedWrite: true,
            approvalExpiresAt: approval.record.expires_at,
            beforeDispatch: async () => {
              // Advance the durable generation before unlinking. A copied
              // approval is stale even if unlink itself fails.
              session = await persistBridgeSession(sessionPath, session, client.session.cookieJar);
              sessionGenerationSpent = true;
              await consumeBridgeApproval(approvalPath);
              approvalConsumed = true;
            }
          });
        } catch (error) {
          dispatchError = error;
          receipt = error?.attemptReceipt;
        }

        if (approvalConsumed) {
          try {
            session = await persistBridgeSession(sessionPath, session, client.session.cookieJar);
          } catch (cause) {
            const persistenceError = new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_PERSISTENCE_FAILED, {
              detail: receipt
                ? 'The one-shot approval was consumed and the request has attempt evidence, but response-updated session credentials could not be persisted. Do not retry the write.'
                : 'The one-shot approval was consumed, but the updated session could not be persisted. Do not retry without first establishing whether a request was sent.',
              stage: 'cli_session',
              requiredAction: {
                kind: 'preserve_attempt_evidence_and_reauthenticate',
                retry_request: false
              },
              cause
            });
            throw attachCliAttemptReceipt(persistenceError, receipt);
          }
        }
        if (dispatchError) {
          if (receipt && dispatchError instanceof BridgeError) {
            dispatchError.requiredAction = {
              ...(dispatchError.requiredAction ?? { kind: 'preserve_attempt_evidence' }),
              retry_request: false
            };
          }
          throw attachCliAttemptReceipt(dispatchError, receipt);
        }
        if (!sessionGenerationSpent || !approvalConsumed) {
          throw new BridgeError(BRIDGE_REFUSAL_CODES.BRIDGE_SESSION_PERSISTENCE_FAILED, {
            detail: 'The request returned without durably consuming its one-shot approval.',
            stage: 'cli_session'
          });
        }
        result = {
          preview,
          receipt,
          approval_capsule: { consumed: true },
          session_state: {
            path: sessionPath,
            session_id: session.record.session_id,
            generation: session.record.generation,
            expires_at: session.record.expires_at,
            persisted: true,
            contains_credentials: true
          }
        };
        break operation;
      }
      throw new Error(`Unknown bridge command: ${subcommand}`);
    }
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  try {
    await client?.clearSession();
  } catch (error) {
    cleanupErrors.push(error);
  }
  try {
    await releaseSessionLock?.();
  } catch (error) {
    cleanupErrors.push(error);
  }
  if (primaryError) {
    if (cleanupErrors.length && primaryError instanceof BridgeError) {
      primaryError.requiredAction = {
        ...(primaryError.requiredAction ?? { kind: 'preserve_primary_bridge_error' }),
        cleanup_warning: {
          code: cleanupErrors[0]?.code ?? 'BRIDGE_SESSION_PERSISTENCE_FAILED',
          detail: 'Session cleanup also failed; the primary dispatch evidence and retry policy still take precedence.'
        }
      };
    }
    throw primaryError;
  }
  if (cleanupErrors.length) throw attachCliAttemptReceipt(cleanupErrors[0], result?.receipt);
  if (result === undefined) throw new Error(`bridge ${subcommand} produced no result`);
  return print(result);
}

async function main() {
  const { positionals, flags } = parse(process.argv.slice(2));
  const [command, subcommand, third] = positionals;
  const helpRequested = booleanSwitch(flags, 'help');
  if (!command || command === 'help' || helpRequested) {
    process.stdout.write(help());
    return;
  }
  // Bridge routing happens before the native client exists. AGENT_TOKEN is
  // therefore never attached to an arbitrary HTML target.
  if (command === 'bridge') return runBridge(subcommand, third, flags);
  const client = new AgentWebClient({
    baseUrl: flags['base-url'] || process.env.AGENT_BASE_URL || 'http://127.0.0.1:4317',
    token: flags.token || process.env.AGENT_TOKEN || 'agent-demo-token',
    runId: flags['run-id'] || randomUUID()
  });

  if (command === 'discover') return print(await client.discover());
  if (command === 'capabilities') return print(await client.capabilities());
  if (command === 'query') {
    const filter = {};
    if (flags.text) filter.text = flags.text;
    if (flags.colour) filter.colour = flags.colour;
    if (flags['max-price-minor']) filter.max_price_minor = Number(flags['max-price-minor']);
    if (booleanSwitch(flags, 'in-stock')) filter.in_stock = true;
    return print(await client.query(filter, { limit: flags.limit ? Number(flags.limit) : 20 }));
  }
  if (command === 'products') return print(await client.products(flags.query || ''));
  if (command === 'product') return print(await client.product(subcommand));
  if (command === 'state') return print(await client.state(flags.scope || 'all'));
  if (command === 'actions') return print(await client.actions());
  if (command === 'preview') {
    if (!subcommand || !flags.args) throw new Error('preview requires ACTION and --args JSON|-');
    return print(await client.preview(subcommand, await jsonArgument(flags.args)));
  }
  if (command === 'commit') {
    if (!subcommand) throw new Error('commit requires PREVIEW_ID');
    return print(await client.commit(subcommand, { idempotencyKey: flags['idempotency-key'] || randomUUID(), confirmation: booleanSwitch(flags, 'confirm') }));
  }
  if (command === 'receipt') return print(await client.receipt(subcommand));
  if (command === 'events') return print({ events: await client.eventsSince(flags.since ? Number(flags.since) : 0) });
  if (command === 'media' && subcommand === 'describe') return print(await client.mediaDescriptor(third));
  if (command === 'media' && subcommand === 'data') return print(await client.mediaData(third));
  if (command === 'media' && subcommand === 'fetch') {
    if (!flags.output) throw new Error('media fetch requires --output FILE');
    const media = await client.mediaBytes(third, { region: flags.region || null });
    await writeFile(flags.output, media.bytes, { mode: 0o600 });
    return print({ output: flags.output, byte_size: media.bytes.length, mime_type: media.mimeType, sha256: media.sha256, source: media.source });
  }
  if (command === 'media' && subcommand === 'read-mark') return print(await client.readInspectionMark(third));
  if (command === 'ask') return print(await client.nlwebAsk(positionals.slice(1).join(' ')));
  if (command === 'automate' && subcommand === 'buy') {
    if (!flags.query) throw new Error('automate buy requires --query TEXT');
    const result = await client.automatePurchase({
      query: flags.query,
      quantity: flags.quantity ? Number(flags.quantity) : 1,
      checkout: booleanSwitch(flags, 'checkout'),
      shippingAddress: flags.address,
      approve: async (preview) => {
        if (booleanSwitch(flags, 'yes')) return true;
        process.stderr.write(`Approval required: ${preview.effect.summary}\nRe-run with --yes after reviewing the preview.\n`);
        return false;
      }
    });
    return print(result);
  }
  if (command === 'file-query') {
    const body = JSON.parse(await readFile(subcommand, 'utf8'));
    return print(await client.query(body.filter ?? {}, { limit: body.limit ?? 20 }));
  }
  throw new Error(`Unknown command: ${positionals.join(' ')}`);
}

main().catch((error) => {
  const attemptReceipt = error?.[CLI_ATTEMPT_RECEIPT];
  const attemptEnvelope = attemptReceipt ? { attempt_receipt: attemptReceipt } : {};
  const output = error instanceof BridgeError
    ? { error: error.toProblem(), ...attemptEnvelope }
    : error instanceof AgentProtocolError || error instanceof UnsupportedAgentSiteError
    ? { error: { code: error.code, message: error.message, status: error.status, details: error.details, request_id: error.requestId }, ...attemptEnvelope }
    : { error: { code: 'CLI_ERROR', message: error.message }, ...attemptEnvelope };
  process.stderr.write(`${JSON.stringify(output, null, 2)}\n`);
  if (error instanceof UnsupportedAgentSiteError) process.exitCode = 4;
  else if (error instanceof BridgeError && ['APPROVAL_REQUIRED', 'APPROVAL_BINDING_MISMATCH', 'CREDENTIAL_BINDING_MISMATCH', 'PREVIEW_STALE', 'BRIDGE_SESSION_CONFLICT'].includes(error.code)) process.exitCode = 5;
  else if (error instanceof BridgeError && error.code.startsWith('AUTH_')) process.exitCode = 6;
  else if (error instanceof BridgeError && ['TLS_REQUIRED', 'SSRF_TARGET_BLOCKED', 'DNS_REBINDING_DETECTED'].includes(error.code)) process.exitCode = 7;
  else if (error instanceof AgentProtocolError && error.status === 401) process.exitCode = 3;
  else if (error instanceof AgentProtocolError && error.status === 409) process.exitCode = 5;
  else process.exitCode = 2;
});
