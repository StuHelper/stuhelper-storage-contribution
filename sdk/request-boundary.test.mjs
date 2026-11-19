import assert from 'node:assert/strict';
import test from 'node:test';
import { contributionAPI } from './browser.ts';

const signal = new AbortController().signal;

test('missing contributions and revision conflicts have distinct outcomes', async () => {
  for (const [status, code] of [[404, 'not_found'], [409, 'conflict']]) {
    const api = contributionAPI(async () => new Response(null, {status}));
    await assert.rejects(api.get(signal, 'record'), {code});
  }
});

test('invalid paths and keys never reach the transport', async () => {
  let calls = 0;
  const api = contributionAPI(async () => { calls++; return new Response(null, {status: 404}); });
  for (const id of ['', '.', '..', 'operations', 'policy', 'options', 'statistics', 'a/b']) {
    await assert.rejects(api.get(signal, id), {code: 'invalid'});
    await assert.rejects(api.execute({kind:'command',key:'valid',id,body:{}},signal), {code:'invalid'});
  }
  await assert.rejects(api.execute({kind:'create',key:'bad\nkey',body:{}},signal), {code:'invalid'});
  assert.equal(calls,0);
});

test('cancellation propagates through fetch and response body reads', async () => {
  for (const phase of ['fetch','body']) {
    const controller=new AbortController();
    const abort=() => {controller.abort(); throw controller.signal.reason;};
    const api=contributionAPI(async () => phase==='fetch'? abort() : {ok:true,status:202,json:abort});
    await assert.rejects(api.execute({kind:'create',key:'_+/=',body:{}},controller.signal),
      err=>err===controller.signal.reason);
  }
});
