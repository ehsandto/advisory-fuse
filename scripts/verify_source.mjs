import fs from 'node:fs';
import './rpc_read_retry.cjs';
import crypto from 'node:crypto';
const address = process.argv[2];
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '')) throw Error('Contract address required');
const res = await fetch('https://studio.genlayer.com/api', {method:'POST',
  headers:{'content-type':'application/json'}, body:JSON.stringify({jsonrpc:'2.0',id:1,
  method:'gen_getContractCode',params:[address]}), signal:AbortSignal.timeout(30000)});
const json = await res.json();
if (json.error || typeof json.result !== 'string') throw Error(JSON.stringify(json.error));
const normalize = text => text.replace(/\r\n/g,'\n').trimEnd()+'\n';
const deployed = normalize(Buffer.from(json.result,'base64').toString('utf8'));
const source = normalize(fs.readFileSync('contracts/AdvisoryFuse.py','utf8'));
const matches = deployed === source;
console.log(JSON.stringify({address,matches,normalized_source_sha256:
  crypto.createHash('sha256').update(deployed).digest('hex')},null,2));
if (!matches) process.exitCode=1;
