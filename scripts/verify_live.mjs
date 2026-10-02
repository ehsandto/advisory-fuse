// Read-only integration verification. No signing keys or write/rebroadcast calls.
import './rpc_read_retry.cjs';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import crypto from 'node:crypto';
import {createClient} from 'genlayer-js';
import {studionet} from 'genlayer-js/chains';

const manifest = JSON.parse(fs.readFileSync('docs/proof-manifest.json','utf8'));
const quote = value => JSON.stringify(value).replace(/[^\x00-\x7f]/g,
  char=>'\\u'+char.charCodeAt(0).toString(16).padStart(4,'0'));
const canonical = value => {
  if(Array.isArray(value)) return '['+value.map(canonical).join(',')+']';
  if(value && typeof value==='object') return '{'+Object.keys(value).sort()
    .map(key=>quote(key)+':'+canonical(value[key])).join(',')+'}';
  return quote(value);
};
const digest = value => crypto.createHash('sha256').update(canonical(value)).digest('hex');
const rpc = async (method,params) => {
  const response=await fetch('https://studio.genlayer.com/api',{method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,method,params}),
    signal:AbortSignal.timeout(30000)});
  assert.ok(response.ok);
  const json=await response.json();
  assert.equal(json.error,undefined);
  return json.result;
};
for(const proof of manifest.transactions){
  const tx=await rpc('eth_getTransactionByHash',[proof.hash]);
  assert.equal(tx?.status,'FINALIZED',proof.label);
  const leader=tx.consensus_data?.leader_receipt?.find(item=>item.mode==='leader');
  assert.equal(leader?.execution_result,proof.execution,proof.label);
  assert.equal(tx.to_address?.toLowerCase(),manifest.address.toLowerCase(),proof.label);
  const votes=tx.consensus_data?.votes??{};
  const validators=[...(tx.consensus_data?.leader_receipt??[]),...(tx.consensus_data?.validators??[])]
    .filter(item=>item.mode==='validator');
  const verified=validators.filter(item=>item.vote==='agree'&&item.execution_result==='SUCCESS');
  if(proof.execution==='SUCCESS') assert.ok(verified.length>=3,'At least three successful agreeing validator executions');
  if(proof.sender) assert.equal(tx.from_address.toLowerCase(),proof.sender.toLowerCase());
  console.log(`${proof.label}: FINALIZED/${proof.execution}; votes=${JSON.stringify(votes)}`);
}
const normalize = text=>text.replace(/\r\n/g,'\n').trimEnd()+'\n';
const source=normalize(Buffer.from(await rpc('gen_getContractCode',[manifest.address]),'base64').toString('utf8'));
assert.equal(source,normalize(fs.readFileSync('contracts/AdvisoryFuse.py','utf8')));
assert.equal(crypto.createHash('sha256').update(source).digest('hex'),manifest.source_sha256);
const client=createClient({chain:studionet});
const read=async (functionName,args)=>await client.readContract({address:manifest.address,functionName,args});
for(const expected of manifest.fuses){
  const fuse=JSON.parse(await read('get_fuse',[expected.id]));
  const record=JSON.parse(await read('get_scan',[expected.id,expected.scan??'scan1']));
  const report=record.report;
  assert.equal(fuse.state,expected.state);
  assert.equal(fuse.latched,expected.latched);
  assert.equal(fuse.current_root,expected.root);
  assert.equal(fuse.pending,'');
  assert.equal(report.root,expected.root);
  assert.equal(report.fuse,expected.id);
  assert.equal(report.spec_root,digest(fuse.spec));
  const {root,...payload}=report;
  assert.equal(root,digest(payload),'Reconstructed evidence root');
  assert.equal(report.decision,expected.decision);
  assert.equal(report.manifest_match,expected.manifest_match);
  assert.equal(report.advisories[0].membership,expected.membership);
  assert.equal(report.advisories[0].semantic.impact,expected.impact);
  for(const old of expected.history??[]){
    const historical=JSON.parse(await read('get_scan',[expected.id,old.scan]));
    assert.equal(historical.report.root,old.root,'Prior resolved reports remain immutable');
  }
  assert.ok(report.sources.every(s=>s.status===200&&s.bytes>0));
  assert.equal(await read('gate',[expected.id,'f'.repeat(64)]),false,'Substituted root must fail');
  const unexpired=Math.floor(Date.now()/1000)<fuse.observed_at+fuse.spec.ttl;
  const expectedGate=fuse.state==='OPEN'&&!fuse.latched&&unexpired;
  assert.equal(await read('gate',[expected.id,expected.root]),expectedGate,'Freshness-sensitive gate');
  console.log(`${expected.id}: ${fuse.state}/${report.decision}; root reconstructs; gate=${expectedGate}`);
}
console.log('Read-only live proof, source and root checks passed. Recovery cases remain mock-only unless separately documented.');
