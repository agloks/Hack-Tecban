const OidcClient = require('../src/oidc-client.js');
const clientConfig = require('./config/client-config-tide-pre-oz2.json');

async function go() {
  const oidcClient = new OidcClient(clientConfig);
  const args = process.argv.slice(2);

  if(args.length == 0){
    console.log("Please provide intentID. e.g. node get-reauth-access-token.js <intentID>");
  }else{
    const intentID = args[0];
    return oidcClient.getTokenByJWTGrant('accounts openid', intentID);
  }

}

go()
  .then(out => console.log(out))
  .catch(err => console.log(err));
