const OidcClient = require('../src/oidc-client.js');
const clientConfig = require('./config/client-config-tide-pre-oz2.json');

async function go() {
  const oidcClient = new OidcClient(clientConfig);
  return oidcClient.getTokenByClientCredentialsGrant('accounts openid');
}

go()
  .then(out => console.log(out))
  .catch(err => console.log(err));
