import './rpc_read_retry.cjs';
const args = process.argv.slice(2);
const error = args.includes('--expect-error');
const wait = args.includes('--wait');
for (const hash of args.filter(arg => !arg.startsWith('--'))) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw Error('Hash required');
  let json;
  const until = Date.now() + (wait ? 150000 : 0);
  do {
  const response = await fetch('https://studio.genlayer.com/api', {method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,
    method:'eth_getTransactionByHash',params:[hash]}),signal:AbortSignal.timeout(30000)});
  json = await response.json();
  if(json.error || !json.result) throw Error(JSON.stringify(json.error));
  if(json.result.status === 'FINALIZED' || Date.now() >= until) break;
  await new Promise(resolve => setTimeout(resolve, 5000));
  } while(true);
  const tx=json.result;
  const leader=tx.consensus_data?.leader_receipt?.find(item=>item.mode==='leader');
  console.log(JSON.stringify({hash,status:tx.status,execution:leader?.execution_result,
    consensus:tx.result_name,...(error?{rejection:leader?.genvm_result?.stderr||leader?.result}:{})}));
  if(tx.status!=='FINALIZED'||leader?.execution_result!==(error?'ERROR':'SUCCESS')) process.exitCode=1;
}
