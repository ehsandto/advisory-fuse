const args = process.argv.slice(2);
const error = args[0] === '--expect-error';
for (const hash of error ? args.slice(1) : args) {
  if (!/^0x[0-9a-fA-F]{64}$/.test(hash)) throw Error('Hash required');
  const response = await fetch('https://studio.genlayer.com/api', {method:'POST',
    headers:{'content-type':'application/json'},body:JSON.stringify({jsonrpc:'2.0',id:1,
    method:'eth_getTransactionByHash',params:[hash]}),signal:AbortSignal.timeout(30000)});
  const json = await response.json();
  if(json.error || !json.result) throw Error(JSON.stringify(json.error));
  const tx=json.result;
  const leader=tx.consensus_data?.leader_receipt?.find(item=>item.mode==='leader');
  console.log(JSON.stringify({hash,status:tx.status,execution:leader?.execution_result,
    consensus:tx.result_name,...(error?{rejection:leader?.genvm_result?.stderr||leader?.result}:{})}));
  if(tx.status!=='FINALIZED'||leader?.execution_result!==(error?'ERROR':'SUCCESS')) process.exitCode=1;
}
