// CLI 0.39.2 compatibility shim: process-local public wallet/network selection.
// It does not alter global account configuration or export signing keys.
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const account = process.env.ADVISORY_FUSE_ACCOUNT;
if (!/^[A-Za-z0-9_-]{1,64}$/.test(account ?? ''))
  throw new Error('Set ADVISORY_FUSE_ACCOUNT to an existing encrypted keystore name');
const configPath = path.resolve(os.homedir(), '.genlayer', 'genlayer-config.json');
const original = fs.readFileSync;
fs.readFileSync = function(file, options) {
  const result = original.apply(this, arguments);
  if (typeof file !== 'string' || path.resolve(file) !== configPath) return result;
  const config = JSON.parse(result.toString());
  const updated = JSON.stringify({...config, activeAccount: account, network: 'studionet'});
  return typeof result === 'string' ? updated : Buffer.from(updated);
};
require('node:module').syncBuiltinESMExports();
