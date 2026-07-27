import test from 'node:test';
import assert from 'node:assert/strict';

import {
  discoverAuthSignals,
  validateAuthorizationServerMetadata
} from '../src/http-bridge/auth-discovery.mjs';
import { BridgeError } from '../src/http-bridge/errors.mjs';
import { buildFormSubmission, compileForms } from '../src/http-bridge/form-compiler.mjs';
import { parseHtmlSource } from '../src/http-bridge/html-source.mjs';

function compile(html, url = 'https://shop.example/login', options = {}) {
  const source = parseHtmlSource({ body: html, url, contentType: 'text/html; charset=utf-8' });
  return { source, ...compileForms(source, options) };
}

function field(form, wireName, occurrence = 0) {
  return form.fields.filter((candidate) => candidate.wire_name === wireName)[occurrence];
}

function stringSchemaAccepts(schema, value) {
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.includes('string')) return false;
  }
  if (Object.hasOwn(schema, 'const') && schema.const !== value) return false;
  if (schema.minLength !== undefined && value.length < schema.minLength) return false;
  if (schema.maxLength !== undefined && value.length > schema.maxLength) return false;
  if (schema.pattern !== undefined && !new RegExp(schema.pattern, 'u').test(value)) return false;
  if (schema.allOf?.some((candidate) => !stringSchemaAccepts(candidate, value))) return false;
  if (schema.anyOf && !schema.anyOf.some((candidate) => stringSchemaAccepts(candidate, value))) return false;
  if (schema.not && stringSchemaAccepts(schema.not, value)) return false;
  return true;
}

test('contract-scoped IDs do not reveal the source path through an offline hash oracle', () => {
  const html = '<form id="login" method="post"><input name="identity"><button value="secret-submit-value">Continue</button></form>';
  const first = compile(html, 'https://app.example/r/7xQ');
  const second = compile(html, 'https://app.example/r/another-capability');
  assert.equal(first.contract.forms[0].form_id, second.contract.forms[0].form_id);
  assert.deepEqual(
    first.contract.forms[0].fields.map((item) => item.field_id),
    second.contract.forms[0].fields.map((item) => item.field_id)
  );
  assert.deepEqual(
    first.contract.actions.map((item) => item.action_id),
    second.contract.actions.map((item) => item.action_id)
  );
});

test('compiles ordered standard form semantics without exposing hidden values', () => {
  const { contract, execution_binding: binding } = compile(`<!doctype html>
    <form id="login" method="post" action="/session">
      <input type="hidden" name="csrf" value="top-secret-token">
      <label for="email">Email</label>
      <input id="email" name="identity" type="email" required maxlength="80">
      <input name="tag" value="first">
      <input name="tag" value="second">
      <input name="password" type="password" required minlength="8">
      <input name="remember" type="checkbox" value="yes" checked>
      <fieldset disabled>
        <legend><input name="legend_value" value="kept"></legend>
        <input name="discarded" value="nope">
      </fieldset>
      <select name="scope" required>
        <option value="">Choose</option>
        <option value="blocked" disabled>Blocked</option>
        <optgroup label="Permissions">
          <option value="account" label="Account">Fallback account text</option>
        </optgroup>
      </select>
      <button name="intent" value="login">Sign in</button>
      <button name="intent" value="recover">Recover</button>
    </form>`);

  assert.equal(contract.executable, true);
  assert.equal(contract.forms.length, 1);
  assert.equal(contract.actions.length, 2);
  assert.equal(JSON.stringify(contract).includes('top-secret-token'), false);
  const publicForm = contract.forms[0];
  assert.equal(publicForm.managed_fields.count, 1);
  assert.equal(field(publicForm, 'password').secret, true);
  assert.equal(field(publicForm, 'identity').label, 'Email');
  assert.equal(field(publicForm, 'identity').schema.minLength, 1);
  assert.equal(field(publicForm, 'tag', 0).field_id === field(publicForm, 'tag', 1).field_id, false);
  assert.equal(field(publicForm, 'discarded'), undefined);
  assert.ok(field(publicForm, 'legend_value'));

  const login = contract.actions.find((action) => action.label === 'Sign in');
  const scope = field(publicForm, 'scope');
  const placeholder = scope.options.find((option) => option.label === 'Choose');
  const blocked = scope.options.find((option) => option.label === 'Blocked');
  const account = scope.options.find((option) => option.label === 'Account');
  assert.equal(placeholder.placeholder, true);
  assert.equal(scope.schema.enum.includes(placeholder.option_id), false);
  assert.equal(scope.schema.enum.includes(blocked.option_id), false);
  assert.equal(scope.schema.enum.includes(account.option_id), true);
  assert.equal(account.group_label, 'Permissions');
  const submission = buildFormSubmission(binding, login.action_id, {
    [field(publicForm, 'identity').field_id]: 'agent@example.com',
    [field(publicForm, 'tag', 0).field_id]: 'alpha',
    [field(publicForm, 'tag', 1).field_id]: 'beta',
    [field(publicForm, 'password').field_id]: 'correct horse',
    [field(publicForm, 'remember').field_id]: true,
    [field(publicForm, 'legend_value').field_id]: 'visible',
    [scope.field_id]: account.option_id
  });
  assert.equal(submission.method, 'POST');
  assert.deepEqual(submission.private_entries, [
    ['csrf', 'top-secret-token'],
    ['identity', 'agent@example.com'],
    ['tag', 'alpha'],
    ['tag', 'beta'],
    ['password', 'correct horse'],
    ['remember', 'yes'],
    ['legend_value', 'visible'],
    ['scope', 'account'],
    ['intent', 'login']
  ]);
});

test('binds ARIA names and fieldset context while keeping long option wire values exact', () => {
  const longOption = `${'x'.repeat(100_100)}-tail`;
  const { contract, execution_binding: binding } = compile(`
    <h2 id="form-title">Account preferences</h2>
    <span id="field-name">Recovery address</span>
    <form aria-labelledby="form-title" method="post" action="/save">
      <fieldset><legend>Danger zone</legend>
        <input name="email" aria-labelledby="field-name">
        <select name="choice"><option label="">${longOption}</option></select>
      </fieldset>
      <button aria-label="Apply account preferences">Unchanged glyph</button>
    </form>`);

  const publicForm = contract.forms[0];
  const email = field(publicForm, 'email');
  const choice = field(publicForm, 'choice');
  const action = contract.actions[0];
  assert.equal(publicForm.label, 'Account preferences');
  assert.equal(email.label, 'Recovery address');
  assert.equal(email.group_label, 'Danger zone');
  assert.equal(action.label, 'Apply account preferences');
  assert.equal(choice.options[0].label.length, 500);

  const submission = buildFormSubmission(binding, action.action_id, {
    [email.field_id]: 'agent@example.com',
    [choice.field_id]: choice.options[0].option_id
  });
  assert.equal(submission.private_entries.find(([name]) => name === 'choice')[1], longOption);
});

test('option fallback values collapse only ASCII whitespace', () => {
  const { contract, execution_binding: binding } = compile(`
    <form method="post" action="/save"><select name="choice">
      <option label="">  alpha&nbsp; beta\n gamma  </option>
    </select><button>Save</button></form>`);
  const publicForm = contract.forms[0];
  const choice = field(publicForm, 'choice');
  assert.equal(choice.options[0].label, 'alpha beta gamma');
  const submission = buildFormSubmission(binding, contract.actions[0].action_id, {
    [choice.field_id]: choice.options[0].option_id
  });
  assert.equal(submission.private_entries[0][1], 'alpha\u00a0 beta gamma');
});

test('external controls keep document order and textarea newlines are normalized', () => {
  const { contract, execution_binding: binding } = compile(`
    <input form="search" name="before" value="A">
    <form id="search" action="/find">
      <textarea name="query">one\ntwo</textarea>
      <button>Search</button>
    </form>
    <input form="search" name="after" value="B">`);
  const action = contract.actions[0];
  const form = contract.forms[0];
  const submission = buildFormSubmission(binding, action.action_id, {
    [field(form, 'before').field_id]: 'A1',
    [field(form, 'query').field_id]: 'line 1\nline 2',
    [field(form, 'after').field_id]: 'B1'
  });
  assert.deepEqual(submission.private_entries, [
    ['before', 'A1'],
    ['query', 'line 1\r\nline 2'],
    ['after', 'B1']
  ]);
  assert.equal(new URL(submission.url).searchParams.get('query'), 'line 1\r\nline 2');
});

test('managed value drift changes only the private instance fingerprint', () => {
  const first = compile('<form id="x" method="post"><input type="hidden" name="csrf" value="one"><input name="q"><button>Go</button></form>');
  const second = compile('<form id="x" method="post"><input type="hidden" name="csrf" value="two"><input name="q"><button>Go</button></form>');
  const firstForm = first.contract.forms[0];
  const secondForm = second.contract.forms[0];
  assert.equal(firstForm.fingerprint, secondForm.fingerprint);
  assert.notEqual(
    first.execution_binding.forms[firstForm.form_id].instance_fingerprint,
    second.execution_binding.forms[secondForm.form_id].instance_fingerprint
  );
});

test('refuses unsupported form mechanics instead of guessing', () => {
  const { contract, findings } = compile(`
    <form action="https://other.example/upload" method="post" enctype="multipart/form-data">
      <input type="file" name="artifact"><input type="image" name="where"><button>Upload</button>
    </form>`);
  assert.equal(contract.executable, false);
  const codes = new Set(findings.map((item) => item.code));
  assert.ok(codes.has('UNSUPPORTED_FILE_CONTROL'));
  assert.ok(codes.has('UNSUPPORTED_IMAGE_SUBMITTER'));
  assert.ok(codes.has('UNSUPPORTED_CROSS_ORIGIN_ACTION'));
  assert.ok(codes.has('UNSUPPORTED_MULTIPART_FORM'));

  const temporal = compile('<form><input name="when" type="datetime-local"><button>Schedule</button></form>');
  assert.equal(temporal.contract.actions[0].executable, false);
  assert.ok(temporal.findings.some((item) => item.code === 'UNSUPPORTED_TEMPORAL_CONTROL'));

  const offsetStep = compile('<form><input name="amount" type="number" min="0.5" step="1"><button>Save</button></form>');
  assert.equal(offsetStep.contract.actions[0].executable, false);
  assert.ok(offsetStep.findings.some((item) => item.code === 'UNSUPPORTED_NUMERIC_STEP_BASE'));

  const readonlyTyped = compile(`<form method="post">
    <input name="when" type="date" readonly value="not-a-date">
    <input name="amount" type="number" readonly value="not-a-number">
    <button>Save</button></form>`);
  assert.equal(readonlyTyped.contract.actions[0].executable, false);
  assert.ok(readonlyTyped.findings.some((item) => item.code === 'UNSUPPORTED_TEMPORAL_CONTROL'));
  assert.ok(readonlyTyped.findings.some((item) => item.code === 'UNSUPPORTED_READONLY_TYPED_CONTROL'));
});

test('refuses form controls whose browser submission semantics are not represented', () => {
  const hardWrap = compile('<form method="post"><textarea name="note" wrap="hard" cols="5"></textarea><button>Save</button></form>');
  assert.equal(hardWrap.contract.actions[0].executable, false);
  assert.ok(hardWrap.findings.some((item) => item.code === 'UNSUPPORTED_HARD_WRAPPED_TEXTAREA'));

  const unnamed = compile('<form method="post"><input type="password" required><input name="note"><button>Save</button></form>');
  assert.equal(unnamed.contract.actions[0].executable, false);
  assert.ok(unnamed.findings.some((item) => item.code === 'UNSUPPORTED_UNNAMED_VALIDATABLE_CONTROL'));
  const bypassed = compile('<form method="post" novalidate><input type="password" required><input name="note"><button>Save</button></form>');
  assert.equal(bypassed.contract.actions[0].executable, true);

  const command = compile('<form><input name="query"><button commandfor="dialog" command="show-modal">Open</button></form>');
  assert.equal(command.contract.actions.length, 0);

  const disabledDefault = compile('<form><input name="query"><input type="submit" disabled></form>');
  assert.equal(disabledDefault.contract.actions.length, 0);

  const blockedImplicit = compile('<form><input name="first"><input name="second"></form>');
  assert.equal(blockedImplicit.contract.actions.length, 0);
  assert.ok(blockedImplicit.findings.some((item) => item.code === 'UNSUPPORTED_IMPLICIT_SUBMISSION'));

  const objectControl = compile('<form><object name="plugin-value"></object><input name="query"><button>Save</button></form>');
  assert.equal(objectControl.contract.actions[0].executable, false);
  assert.ok(objectControl.findings.some((item) => item.code === 'UNSUPPORTED_OBJECT_CONTROL'));
});

test('matches enumerated-attribute whitespace and managed charset semantics', () => {
  const spaced = compile(`<form method=" post " enctype=" text/plain ">
    <input name="value"><button type=" button ">Default submitter</button></form>`);
  assert.equal(spaced.contract.actions.length, 1);
  assert.equal(spaced.contract.actions[0].method, 'GET');
  assert.equal(spaced.contract.actions[0].enctype, 'application/x-www-form-urlencoded');

  const charset = compile(`<form method="post">
    <input name="_charset_" readonly value="must-stay">
    <input name="_charset_" type="hidden" value="ignored-by-browser">
    <button>Save</button></form>`);
  const action = charset.contract.actions[0];
  const submission = buildFormSubmission(charset.execution_binding, action.action_id, {});
  assert.deepEqual(submission.private_entries, [
    ['_charset_', 'must-stay'],
    ['_charset_', 'UTF-8']
  ]);
});

test('an image submitter does not disable an independent standard submit button', () => {
  const { contract } = compile(`<form method="post" action="/save">
    <input name="value"><input type="image" src="/button.png"><button>Save normally</button>
  </form>`);
  assert.equal(contract.actions.length, 1);
  assert.equal(contract.actions[0].executable, true);
  const imageFinding = contract.findings.find((item) => item.code === 'UNSUPPORTED_IMAGE_SUBMITTER');
  assert.equal(imageFinding.blocking, false);
});

test('respects header and meta form-action CSP instead of bypassing browser policy', () => {
  const html = '<form action="/apply" method="post"><input name="value"><button>Apply</button></form>';
  const headerBlocked = compile(html, 'https://shop.example/settings', {
    contentSecurityPolicy: "default-src 'self'; form-action 'none'"
  });
  assert.equal(headerBlocked.contract.actions[0].executable, false);
  assert.ok(headerBlocked.findings.some((item) => item.code === 'UNSUPPORTED_CSP_FORM_ACTION'));

  const metaBlocked = compile(`<meta http-equiv="Content-Security-Policy" content="form-action 'none'">${html}`);
  assert.equal(metaBlocked.contract.actions[0].executable, false);

  const selfAllowed = compile(html, 'https://shop.example/settings', {
    contentSecurityPolicy: "default-src 'none'; form-action 'self'"
  });
  assert.equal(selfAllowed.contract.actions[0].executable, true);
});

test('reproduces CSP sandbox and base-uri restrictions instead of bypassing them', () => {
  const html = '<form action="/apply" method="post"><input name="value"><button>Apply</button></form>';
  const sandboxed = compile(html, 'https://shop.example/settings', {
    contentSecurityPolicy: "sandbox allow-scripts; form-action 'self'"
  });
  assert.equal(sandboxed.contract.actions[0].executable, false);
  assert.ok(sandboxed.findings.some((item) => item.code === 'UNSUPPORTED_CSP_SANDBOX'));

  const formsAllowed = compile(html, 'https://shop.example/settings', {
    contentSecurityPolicy: "sandbox allow-forms allow-same-origin; form-action 'self'"
  });
  assert.equal(formsAllowed.contract.actions[0].executable, true);

  const opaqueOrigin = compile(html, 'https://shop.example/settings', {
    contentSecurityPolicy: "sandbox allow-forms; form-action 'self'"
  });
  assert.equal(opaqueOrigin.contract.actions[0].executable, false);
  assert.ok(opaqueOrigin.findings.some((item) => item.code === 'UNSUPPORTED_CSP_SANDBOX'));

  const rejectedBase = compile(`<base href="https://other.example/prefix/">${html}`, 'https://shop.example/settings', {
    contentSecurityPolicy: "base-uri 'none'; form-action 'self'"
  });
  assert.equal(rejectedBase.contract.actions[0].executable, true);
  assert.equal(rejectedBase.contract.actions[0].target.origin, 'https://shop.example');
  assert.equal(rejectedBase.contract.actions[0].target.path, '/apply');
  assert.ok(rejectedBase.findings.some((item) => item.code === 'CSP_BASE_URI_IGNORED' && item.blocking === false));

  const metaSandboxIgnored = compile(`<meta http-equiv="Content-Security-Policy" content="sandbox">${html}`);
  assert.equal(metaSandboxIgnored.contract.actions[0].executable, true);
});

test('validates intrinsic email, finite-number, and step rules unless validation is bypassed', () => {
  const strict = compile(`<form method="post" action="/save">
    <input name="email" type="email" required>
    <input name="quantity" type="number" min="0" max="10" step="0.5" required>
    <button>Save</button></form>`);
  const strictForm = strict.contract.forms[0];
  const strictAction = strict.contract.actions[0];
  const email = field(strictForm, 'email');
  const quantity = field(strictForm, 'quantity');
  assert.equal(quantity.schema.multipleOf, 0.5);
  assert.equal(strictAction.input_schema.properties[quantity.field_id].multipleOf, 0.5);
  const validEmail = { [email.field_id]: 'agent@example.com' };

  assert.throws(
    () => buildFormSubmission(strict.execution_binding, strictAction.action_id, {
      [email.field_id]: 'not-an-email', [quantity.field_id]: 1
    }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  assert.throws(
    () => buildFormSubmission(strict.execution_binding, strictAction.action_id, {
      ...validEmail, [quantity.field_id]: Number.NaN
    }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  assert.throws(
    () => buildFormSubmission(strict.execution_binding, strictAction.action_id, {
      ...validEmail, [quantity.field_id]: 1.25
    }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  assert.equal(buildFormSubmission(strict.execution_binding, strictAction.action_id, {
    ...validEmail, [quantity.field_id]: 1.5
  }).method, 'POST');

  const bypassed = compile(`<form novalidate method="post" action="/save">
    <input name="email" type="email" required>
    <input name="quantity" type="number" min="0" max="10" step="0.5" required>
    <button>Save anyway</button></form>`);
  const bypassedForm = bypassed.contract.forms[0];
  const bypassedAction = bypassed.contract.actions[0];
  const bypassedSubmission = buildFormSubmission(bypassed.execution_binding, bypassedAction.action_id, {
    [field(bypassedForm, 'email').field_id]: 'not-an-email',
    [field(bypassedForm, 'quantity').field_id]: 1.25
  });
  assert.equal(bypassedAction.validation_bypassed, true);
  assert.deepEqual(new Set(bypassedAction.input_schema.required), new Set([
    field(bypassedForm, 'email').field_id,
    field(bypassedForm, 'quantity').field_id
  ]));
  assert.equal(bypassedAction.input_schema.properties[field(bypassedForm, 'quantity').field_id].multipleOf, undefined);
  assert.equal(bypassedSubmission.method, 'POST');

  const rangeCompiled = compile('<form><input name="level" type="range"><button>Set</button></form>');
  const rangeForm = rangeCompiled.contract.forms[0];
  const rangeAction = rangeCompiled.contract.actions[0];
  const level = field(rangeForm, 'level');
  assert.equal(level.schema.minimum, 0);
  assert.equal(level.schema.maximum, 100);
  assert.throws(
    () => buildFormSubmission(rangeCompiled.execution_binding, rangeAction.action_id, { [level.field_id]: 101 }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );

  for (const novalidate of ['', ' novalidate']) {
    const colorCompiled = compile(`<form method="post"${novalidate}><input name="tone" type="color"><button>Set</button></form>`);
    const colorAction = colorCompiled.contract.actions[0];
    const tone = field(colorCompiled.contract.forms[0], 'tone');
    assert.equal(stringSchemaAccepts(colorAction.input_schema.properties[tone.field_id], ''), false);
    assert.throws(
      () => buildFormSubmission(colorCompiled.execution_binding, colorAction.action_id, { [tone.field_id]: '' }),
      (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
    );
    assert.equal(buildFormSubmission(colorCompiled.execution_binding, colorAction.action_id, {
      [tone.field_id]: '#12aBcF'
    }).method, 'POST');
  }
});

test('published email and URL schemas accept exactly the values the runtime accepts', () => {
  const compiled = compile(`<form method="post" action="/profile">
    <input name="recipients" type="email" multiple required>
    <input name="backup" type="email">
    <input name="homepage" type="url">
    <input name="required_homepage" type="url" required>
    <button>Save</button></form>`);
  const form = compiled.contract.forms[0];
  const action = compiled.contract.actions[0];
  const recipients = field(form, 'recipients');
  const backup = field(form, 'backup');
  const homepage = field(form, 'homepage');
  const requiredHomepage = field(form, 'required_homepage');
  const recipientSchema = action.input_schema.properties[recipients.field_id];
  const backupSchema = action.input_schema.properties[backup.field_id];
  const homepageSchema = action.input_schema.properties[homepage.field_id];
  const requiredHomepageSchema = action.input_schema.properties[requiredHomepage.field_id];
  const patternsAccept = (schema, value) => [
    ...(schema.pattern ? [schema.pattern] : []),
    ...(schema.allOf ?? []).flatMap((item) => item.pattern ? [item.pattern] : [])
  ].every((pattern) => new RegExp(pattern, 'u').test(value));

  assert.equal(patternsAccept(recipientSchema, 'not-an-email'), false);
  assert.equal(patternsAccept(recipientSchema, 'first@example.com, second@example.org'), true);
  assert.equal(patternsAccept(backupSchema, ''), true);
  assert.equal(stringSchemaAccepts(homepageSchema, ''), true);
  assert.equal(stringSchemaAccepts(homepageSchema, 'not an absolute URL'), false);
  assert.equal(stringSchemaAccepts(homepageSchema, 'https://example.com/a b'), false);
  assert.equal(stringSchemaAccepts(homepageSchema, 'https://example.com:99999/'), false);
  assert.equal(stringSchemaAccepts(homepageSchema, 'custom://@@'), false);
  assert.equal(stringSchemaAccepts(homepageSchema, 'custom://host:abc'), false);
  assert.equal(stringSchemaAccepts(homepageSchema, 'https://example.com/a%20b'), true);
  assert.equal(stringSchemaAccepts(homepageSchema, 'mailto:agent@example.com'), true);
  assert.equal(stringSchemaAccepts(homepageSchema, 'custom://user:pass@host:8080/path'), true);
  assert.equal(stringSchemaAccepts(requiredHomepageSchema, ''), false);
  assert.equal(stringSchemaAccepts(requiredHomepageSchema, 'HTTPS://example.com/profile'), true);
  assert.equal(buildFormSubmission(compiled.execution_binding, action.action_id, {
    [recipients.field_id]: 'first@example.com, second@example.org',
    [backup.field_id]: '',
    [homepage.field_id]: '',
    [requiredHomepage.field_id]: 'https://example.com/a%20b'
  }).method, 'POST');
  assert.throws(
    () => buildFormSubmission(compiled.execution_binding, action.action_id, {
      [recipients.field_id]: 'not-an-email',
      [backup.field_id]: '',
      [homepage.field_id]: '',
      [requiredHomepage.field_id]: 'https://example.com/a%20b'
    }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
  for (const invalidUrl of [
    'not an absolute URL',
    'https://example.com/a b',
    'https://example.com:99999/',
    'custom://@@',
    'custom://host:abc'
  ]) {
    assert.throws(
      () => buildFormSubmission(compiled.execution_binding, action.action_id, {
        [recipients.field_id]: 'first@example.com',
        [backup.field_id]: '',
        [homepage.field_id]: invalidUrl,
        [requiredHomepage.field_id]: 'https://example.com/profile'
      }),
      (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
    );
  }

  const bypassed = compile(`<form novalidate method="post" action="/profile">
    <input name="recipients" type="email" multiple required>
    <input name="homepage" type="url" required>
    <button>Save anyway</button></form>`);
  const bypassedForm = bypassed.contract.forms[0];
  const bypassedAction = bypassed.contract.actions[0];
  const bypassedRecipients = field(bypassedForm, 'recipients');
  const bypassedHomepage = field(bypassedForm, 'homepage');
  for (const bypassedField of [bypassedRecipients, bypassedHomepage]) {
    assert.deepEqual(bypassedAction.input_schema.properties[bypassedField.field_id], {
      type: 'string',
      title: bypassedField.label || bypassedField.wire_name,
      pattern: '^[^\\r\\n]*$'
    });
  }
  assert.equal(buildFormSubmission(bypassed.execution_binding, bypassedAction.action_id, {
    [bypassedRecipients.field_id]: 'not-an-email',
    [bypassedHomepage.field_id]: 'not an absolute URL'
  }).method, 'POST');
});

test('editable defaults are never submitted without explicit agent values', () => {
  const compiled = compile(`<form method="post" action="/save">
    <input name="amount" value="1000000">
    <input name="notify" type="checkbox" value="yes" checked>
    <select name="scope"><option value="all" selected>Everything</option><option value="one">One</option></select>
    <input name="optional_code" value="DEFAULT">
    <button>Save</button></form>`);
  const formContract = compiled.contract.forms[0];
  const action = compiled.contract.actions[0];
  assert.ok(formContract.fields.every((item) => item.agent_input_required));
  assert.deepEqual(new Set(action.input_schema.required), new Set(formContract.fields.map((item) => item.field_id)));
  assert.throws(
    () => buildFormSubmission(compiled.execution_binding, action.action_id, {}),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );

  const scope = field(formContract, 'scope');
  const one = scope.options.find((option) => option.label === 'One');
  const submission = buildFormSubmission(compiled.execution_binding, action.action_id, {
    [field(formContract, 'amount').field_id]: '5',
    [field(formContract, 'notify').field_id]: false,
    [scope.field_id]: one.option_id,
    [field(formContract, 'optional_code').field_id]: ''
  });
  assert.deepEqual(submission.private_entries, [
    ['amount', '5'],
    ['scope', 'one'],
    ['optional_code', '']
  ]);
  assert.equal(submission.body.includes('1000000'), false);

  const omittedOptionalSelection = buildFormSubmission(compiled.execution_binding, action.action_id, {
    [field(formContract, 'amount').field_id]: '5',
    [field(formContract, 'notify').field_id]: false,
    [scope.field_id]: null,
    [field(formContract, 'optional_code').field_id]: ''
  });
  assert.equal(omittedOptionalSelection.private_entries.some(([name]) => name === 'scope'), false);

  const multiple = compile(`<form method="post" action="/save">
    <select name="roles" multiple required>
      <option value="reader">Reader</option>
      <option value="blocked" disabled>Blocked</option>
      <option value="writer">Writer</option>
    </select><button>Save roles</button></form>`);
  const multipleForm = multiple.contract.forms[0];
  const multipleAction = multiple.contract.actions[0];
  const roles = field(multipleForm, 'roles');
  const reader = roles.options.find((option) => option.label === 'Reader');
  const blockedRole = roles.options.find((option) => option.label === 'Blocked');
  assert.equal(roles.schema.minItems, 1);
  assert.equal(roles.schema.uniqueItems, true);
  assert.equal(roles.schema.items.enum.includes(blockedRole.option_id), false);
  assert.throws(
    () => buildFormSubmission(multiple.execution_binding, multipleAction.action_id, {
      [roles.field_id]: [reader.option_id, reader.option_id]
    }),
    (error) => error instanceof BridgeError && error.code === 'INVALID_BRIDGE_DATA'
  );
});

test('bounds inference work for adversarially large documents', () => {
  const html = `<form action="/save">${'<span></span>'.repeat(50_001)}<input name="value"><button>Save</button></form>`;
  const compiled = compile(html);
  assert.equal(compiled.contract.executable, false);
  assert.equal(compiled.contract.forms.length, 0);
  assert.ok(compiled.findings.some((item) => item.code === 'HTML_ELEMENT_LIMIT_EXCEEDED' && item.blocking));

  const repeatedLabels = `${'<label for="shared">Shared label</label>'.repeat(4_000)}${'<input id="shared" name="value">'.repeat(4_000)}`;
  const started = performance.now();
  const linear = compile(`<form action="/save">${repeatedLabels}<button>Save</button></form>`);
  assert.equal(linear.contract.executable, true);
  assert.ok(performance.now() - started < 1_000, 'repeated for= labels must not cause quadratic aggregation');
});

test('never decodes non-ASCII bytes under an ASCII declaration as UTF-8 form values', () => {
  const source = parseHtmlSource({
    body: Buffer.from('<form><input type="hidden" name="managed" value="é"><button>Go</button></form>', 'utf8'),
    url: 'https://shop.example/form',
    contentType: 'text/html; charset=us-ascii'
  });
  assert.equal(source.document, null);
  assert.ok(source.findings.some((item) => item.code === 'UNSUPPORTED_NON_UTF8' && item.blocking));

  const ascii = parseHtmlSource({
    body: Buffer.from('<form><input type="hidden" name="managed" value="ascii"><button>Go</button></form>', 'ascii'),
    url: 'https://shop.example/form',
    contentType: 'text/html; charset=us-ascii'
  });
  assert.ok(ascii.document);
  assert.equal(compileForms(ascii).contract.actions[0].executable, true);
});

test('refuses untrusted HTML patterns without evaluating catastrophic regexes', () => {
  const started = performance.now();
  const compiled = compile('<form method="post" action="/save"><input name="value" pattern="(a+)+$"><button>Save</button></form>');
  assert.equal(compiled.contract.actions[0].executable, false);
  assert.ok(compiled.findings.some((item) => item.code === 'UNSUPPORTED_PATTERN_VALIDATION' && item.blocking));
  assert.equal(JSON.stringify(compiled.contract).includes('(a+)+$'), false);
  assert.equal(compiled.contract.forms[0].fields[0].constraints.pattern_present, true);
  const value = field(compiled.contract.forms[0], 'value');
  assert.throws(
    () => buildFormSubmission(compiled.execution_binding, compiled.contract.actions[0].action_id, {
      [value.field_id]: `${'a'.repeat(100_000)}!`
    }),
    (error) => error instanceof BridgeError && error.code === 'FORM_SEMANTICS_UNSUPPORTED'
  );
  assert.ok(performance.now() - started < 500, 'pattern refusal must remain bounded and synchronous');
});

test('page scripts lower input completeness instead of being mistaken for browser equivalence', () => {
  const { contract } = compile('<script src="/app.js"></script><form><input name="q"><button>Search</button></form>');
  assert.equal(contract.actions[0].executable, true);
  assert.equal(contract.actions[0].assurance.input_completeness, 'heuristic');
  assert.ok(contract.forms[0].findings.some((item) => item.code === 'PAGE_SCRIPT_NOT_EXECUTED'));

  const dataOnly = compile('<script type="application/ld+json">{"name":"data"}</script><form><input name="q"><button>Search</button></form>');
  assert.equal(dataOnly.contract.actions[0].assurance.input_completeness, 'direct');
});

test('auth discovery distinguishes direct interaction evidence from text heuristics', () => {
  const source = parseHtmlSource({
    url: 'https://id.example/login',
    contentType: 'text/html',
    body: `<form><input name="password" type="password"><input name="otp" autocomplete="one-time-code" required>
      <div class="cf-turnstile" data-sitekey="public-key"></div></form>
      <input autocomplete="username webauthn"><script src="https://challenges.cloudflare.com/turnstile/v0/api.js"></script>
      <p>We can email a magic link.</p>`
  });
  const auth = discoverAuthSignals(source);
  assert.equal(auth.authenticated, 'unverified');
  assert.ok(auth.signals.some((item) => item.kind === 'credential_form' && item.strength === 'direct'));
  assert.ok(auth.signals.some((item) => item.kind === 'magic_link' && item.strength === 'heuristic'));
  const required = new Set(auth.required_interactions.map((item) => item.code));
  assert.ok(required.has('AUTH_OTP_REQUIRED'));
  assert.ok(required.has('AUTH_CAPTCHA_REQUIRED'));
  assert.ok(auth.interaction_candidates.some((item) => item.code === 'AUTH_PASSKEY_REQUIRED' && item.blocking === false));

  const ordinaryLink = discoverAuthSignals(parseHtmlSource({
    url: 'https://app.example/form',
    contentType: 'text/html',
    body: '<form><input name="q"><a href="https://www.google.com/privacy">Privacy</a><button>Go</button></form>'
  }));
  assert.equal(ordinaryLink.signals.some((item) => item.kind === 'captcha'), false);
});

test('authorization metadata validation requires safe absolute endpoints and external user authorization', () => {
  const valid = validateAuthorizationServerMetadata({
    issuer: 'https://id.example',
    authorization_endpoint: 'https://id.example/authorize',
    token_endpoint: 'https://id.example/token',
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256']
  });
  assert.equal(valid.authorization_code_supported, true);
  assert.equal(valid.pkce_s256_advertised, true);
  assert.equal(valid.interaction.code, 'AUTH_EXTERNAL_USER_AGENT_REQUIRED');
  assert.throws(
    () => validateAuthorizationServerMetadata({ issuer: 'http://id.example', authorization_endpoint: 'https://id.example/authorize' }),
    (error) => error instanceof BridgeError && error.code === 'AUTH_METADATA_INVALID'
  );
});
