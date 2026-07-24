#!/usr/bin/env node
import { readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { AgentProtocolError, AgentWebClient, UnsupportedAgentSiteError } from './client.mjs';

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

Global flags:
  --base-url URL        Site origin (default AGENT_BASE_URL or http://127.0.0.1:4317)
  --token TOKEN         Bearer token (default AGENT_TOKEN)

Commands:
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

async function main() {
  const { positionals, flags } = parse(process.argv.slice(2));
  const [command, subcommand, third] = positionals;
  if (!command || command === 'help' || flags.help) {
    process.stdout.write(help());
    return;
  }
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
    if (flags['in-stock']) filter.in_stock = true;
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
    return print(await client.commit(subcommand, { idempotencyKey: flags['idempotency-key'] || randomUUID(), confirmation: Boolean(flags.confirm) }));
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
      checkout: Boolean(flags.checkout),
      shippingAddress: flags.address,
      approve: async (preview) => {
        if (flags.yes) return true;
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
  const output = error instanceof AgentProtocolError || error instanceof UnsupportedAgentSiteError
    ? { error: { code: error.code, message: error.message, status: error.status, details: error.details, request_id: error.requestId } }
    : { error: { code: 'CLI_ERROR', message: error.message } };
  process.stderr.write(`${JSON.stringify(output, null, 2)}\n`);
  if (error instanceof UnsupportedAgentSiteError) process.exitCode = 4;
  else if (error instanceof AgentProtocolError && error.status === 401) process.exitCode = 3;
  else if (error instanceof AgentProtocolError && error.status === 409) process.exitCode = 5;
  else process.exitCode = 2;
});
