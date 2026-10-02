import {createClient} from 'genlayer-js';
import './rpc_read_retry.cjs';
import {studionet} from 'genlayer-js/chains';
const [address, method, ...args] = process.argv.slice(2);
if (!/^0x[0-9a-fA-F]{40}$/.test(address ?? '') ||
    !['get_fuse','get_scan','gate','event_count'].includes(method)) throw Error('Allowed read required');
const client = createClient({chain:studionet});
const result = await client.readContract({address,functionName:method,args});
console.log(typeof result === 'string' ? JSON.stringify(JSON.parse(result),null,2) : JSON.stringify(result));
