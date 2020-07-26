const Validator = require('jsonschema').Validator;
const Http = require('ozone-http-client');
const Jwt = require('ozone-jwt');
const uuidv4 = require('uuid/v4');
const log = require('loglevel');
const _ = require('lodash');
const path = require('path');
const schema = require('./oidc-client-schema.json');

class OidcClient {
  constructor(clientConfig, baseFolder) {
    const logLevel = _.get(clientConfig, 'logLevels.oidcClient');
    log.setLevel(logLevel || 'silent');

    // validate the client config
    log.info('OidcClient.ctor: validating client config - start');
    const jsonSchemaValidator = new Validator();
    const validationResult = jsonSchemaValidator.validate(clientConfig, schema);
    if (validationResult.errors.length > 0) {
      log.error('OidcClient.ctor: validating client config - failed');
      throw new Error(`client config failed validation. ${validationResult.errors}`);
    }
    log.info('OidcClient.ctor: validating client config - done');

    this.httpLogLevel = _.get(clientConfig, 'logLevels.http');
    this.jwtLogLevel = _.get(clientConfig, 'logLevels.jwt');

    process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0; // eslint-disable-line dot-notation

    this.clientConfig = _.clone(clientConfig);
    
    if (baseFolder !== undefined) {
      log.info(`Base folder is ${baseFolder}. Adjusting all paths`);
      if (clientConfig.certs !== undefined) {
        this.clientConfig.certs = {
          ca: path.join(baseFolder, _.get(clientConfig, 'certs.ca')),
          cert: path.join(baseFolder, _.get(clientConfig, 'certs.cert')),
          key: path.join(baseFolder, _.get(clientConfig, 'certs.key'))
        };
      }

      if (_.get(clientConfig, 'signingKeyFileName') !== undefined) {
        this.clientConfig.signingKeyFileName = path.join(baseFolder,  _.get(clientConfig, 'signingKeyFileName'));
      }
    }
  }
  
  async getWellKnownConfiguration() {
    log.info('OidcClient.getWellKnownConfiguration: get .wellknown - start');
    if (this.wellKnownConfiguration !== undefined) {
      log.info('OidcClient.getWellKnownConfiguration: using cached value');
      return this.wellKnownConfiguration;
    }

    log.info(`OidcClient.getWellKnownConfiguration: retrieving from ${this.clientConfig.issuer}`);
    const wkc = await Http.do({ url: this.clientConfig.issuer, parseJson: true, logLevel: this.httpLogLevel });
    log.debug('OidcClient.getWellKnownConfiguration: retrieved');
    log.debug(wkc);
    log.debug('-------------------------');

    if ((wkc.status === 200) && (wkc.json !== undefined)) {
      this.wellKnownConfiguration = wkc.json;
    } else {
      log.error('OidcClient.getWellKnownConfiguration: get .wellknown - failed');
      throw new Error(`Could not retrieve .well-known ${wkc.data}`);
    }

    log.info('OidcClient.getWellKnownConfiguration: get .wellknown - done');
    return this.wellKnownConfiguration;
  }

  async _getAccessToken(scope, grantType, fields) {
    // ensure we have the .well-known
    await this.getWellKnownConfiguration();

    if (fields === undefined) {
      fields = {};
    }
    fields.grant_type = grantType;
    fields.scope = scope;


    // start building up the request params
    const params = {
      verb: 'post',
      headers: {
        'content-type': 'application/x-www-form-urlencoded'
      },
      fields,
      certs: this.clientConfig.certs,
      parseJson: true,
      logLevel: this.httpLogLevel
    };

    // get the token endpoint
    params.url = this.wellKnownConfiguration.token_endpoint;
    if (params.url === undefined) {
      throw new Error('token_endpoint not defined in oidc well-known configuration');
    }

    // add in whatever is required for authentication
    await this._addAuthenticationParams(params, grantType);

    // make the call
    const response = await Http.do(params);
    if (response.json !== undefined) {
      return response.json;
    }

    throw new Error(`failed to get access token ${response.data}`);
  }

  async _getReauthAccessToken(scope, grantType, intentID, fields) {
    // ensure we have the .well-known
    await this.getWellKnownConfiguration();

    if (fields === undefined) {
      fields = {};
    }
    fields.grant_type = grantType;
    fields.scope = scope;

    // start building up the request params
    const params = {
      verb: 'post',
      headers: {
        'content-type': 'application/x-www-form-urlencoded'
      },
      fields,
      certs: this.clientConfig.certs,
      parseJson: true,
      logLevel: this.httpLogLevel
    };

    // get the token endpoint
    params.url = this.wellKnownConfiguration.token_endpoint;
    if (params.url === undefined) {
      throw new Error('token_endpoint not defined in oidc well-known configuration');
    }

    // add in whatever is required for authentication
    await this._addAuthenticationParams(params, grantType, intentID);

    // make the call
    const response = await Http.do(params);
    if (response.json !== undefined) {
      return response.json;
    }

    throw new Error(`failed to get access token ${response.data}`);
  }

  async getTokenByClientCredentialsGrant(scope) {
    return this._getAccessToken(scope, 'client_credentials');
  }

  async getTokenByRefreshGrant(scope, refreshToken) {
    return this._getAccessToken(scope, 'refresh_token', { refresh_token: refreshToken });
  }

  async getTokenByJWTGrant(scope, intentID) {
    return this._getReauthAccessToken(scope, 'urn:ietf:params:oauth:grant-type:jwt-bearer', intentID);
  }

  async getTokenByCibaGrant(scope, authReqId) {
    return this._getAccessToken(
      scope,
      'urn:openid:params:grant-type:ciba',
      { auth_req_id: authReqId }
    );
  }

  async getTokenByAuthCodeGrant(scope, redirectUri, code) {
    return this._getAccessToken(
      scope,
      'authorization_code',
      { 
        code,
        redirect_uri: redirectUri 
      }
    );
  }

  async doFapiBcAuthorize(loginHintJwt, scope, state) {
    // ensure we have the .well-known
    await this.getWellKnownConfiguration();
    if (this.wellKnownConfiguration === undefined) {
      throw new Error('could not retrieve oidc well-known configuration');
    }

    if (this.wellKnownConfiguration.backchannel_authentication_endpoint === undefined) {
      throw new Error('server does not have a backchannel_authentication_endpoint specified');
    }

    if (this.clientConfig.backchannel_authentication_request_signing_alg === undefined) {
      throw new Error('backchannel_authentication_request_signing_alg is not specified in client config');
    }

    // build the login hint jws
    const loginHintJws = await Jwt.sign({
      header: { 'alg': 'none' },
      body: loginHintJwt
    });

    // build the request jwt
    const requestJwt = {
      aud: this.wellKnownConfiguration.issuer,
      exp: (Date.now() / 1000) + 120,
      iss: this.clientConfig.client_id,
      nonce: uuidv4(),
      state,
      scope,
      client_notification_token: uuidv4(),
      login_hint_token: loginHintJws
    };

    // sign the request jwt
    const requestJws = await Jwt.sign({
      header: {
        alg: this.clientConfig.backchannel_authentication_request_signing_alg,
        kid: this.clientConfig.signingKeyKid
      },
      body: requestJwt,
      signingKeyFileName: this.clientConfig.signingKeyFileName
    });

    // start building up the request params
    const httpRequestParams = {
      verb: 'post',
      url: this.wellKnownConfiguration.backchannel_authentication_endpoint,
      headers: {
        'content-type': 'application/x-www-form-urlencoded'
      },
      fields: {
        'request': requestJws
      },
      certs: this.clientConfig.certs,
      parseJson: true
    };

    // add in whatever is required for authentication
    await this._addAuthenticationParams(httpRequestParams);

    // make the call
    const response = await Http.do(httpRequestParams);
    if (response.json !== undefined) {
      return response.json;
    }

    throw new Error(`failed to call bc-authorize: ${response.data}`);
  }

  async _addAuthenticationParams(params, grantType, intentID) {
    if (this.clientConfig.token_endpoint_auth_method === undefined) {
      throw new Error('token_endpoint_auth_method missing in client config');
    }

    switch (this.clientConfig.token_endpoint_auth_method) {
      case 'client_secret_basic':
        await this._addClientSecretBasicAuthenticationMethod(params);
        break;

      case 'private_key_jwt':
        if (grantType === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
          await this._addPrivateKeyJwtAuthenticationMethodForReauth(params, intentID);
        } else {
          await this._addPrivateKeyJwtAuthenticationMethod(params);
        }
        
        break;

      case 'tls_client_auth':
        await this._addTlsClientAuthAuthenticationMethod(params);
        break;

      default:
        throw new Error(`token_endpoint_auth_method ${this.client.token_endpoint_auth_method} is not supported`);
    }
  }

  async _addClientSecretBasicAuthenticationMethod(params) {
    if (this.clientConfig.client_id === undefined) {
      throw new Error('client_id missing in client config');
    }

    if (this.clientConfig.client_secret === undefined) {
      throw new Error('client_secret missing in client config');
    }

    const token = Buffer
      .from(`${this.clientConfig.client_id}:${this.clientConfig.client_secret}`)
      .toString('base64');

    params.headers.authorization = `Basic ${token}`;
  }

  async _addTlsClientAuthAuthenticationMethod(params) {
    if (this.clientConfig.client_id === undefined) {
      throw new Error('client_id missing in client config');
    }
    params.fields.client_id = this.clientConfig.client_id;
  }

  async _addPrivateKeyJwtAuthenticationMethod(params) {
    if (this.clientConfig.token_endpoint_auth_signing_alg === undefined) {
      throw new Error('token_endpoint_auth_signing_alg is missing in client config');
    }

    if ((this.clientConfig.token_endpoint_auth_signing_alg === 'none') ||
      (this.clientConfig.token_endpoint_auth_signing_alg === 'HS256')) {
      throw new Error('token_endpoint_auth_signing_alg cannot be HS256 or none for token_endpoint_auth_method private_key_jwt');
    }

    if (this.clientConfig.signingKeyKid === undefined) {
      throw new Error('signingKeyKid is missing in client config');
    }

    if (this.clientConfig.signingKeyFileName === undefined) {
      throw new Error('signingKeyFIleName is missing in client config');
    }

    const iat = Date.now() / 1000;
    const jwt = {
      header: {
        alg: this.clientConfig.token_endpoint_auth_signing_alg,
        kid: this.clientConfig.signingKeyKid
      },
      body: {
        iss: this.clientConfig.client_id,
        sub: this.clientConfig.client_id,
        aud: this.wellKnownConfiguration.token_endpoint,
        jti: uuidv4(),
        exp: iat + 30,
        iat
      },
      signingKeyFileName: this.clientConfig.signingKeyFileName
    };

    const jws = await Jwt.sign(jwt);

    // set other http params
    params.fields.client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'; // eslint-disable-line no-param-reassign
    params.fields.client_assertion = jws; // eslint-disable-line no-param-reassign
  }

  async _addPrivateKeyJwtAuthenticationMethodForReauth(params, intentID) {
    if (this.clientConfig.token_endpoint_auth_signing_alg === undefined) {
      throw new Error('token_endpoint_auth_signing_alg is missing in client config');
    }

    if ((this.clientConfig.token_endpoint_auth_signing_alg === 'none') ||
      (this.clientConfig.token_endpoint_auth_signing_alg === 'HS256')) {
      throw new Error('token_endpoint_auth_signing_alg cannot be HS256 or none for token_endpoint_auth_method private_key_jwt');
    }

    if (this.clientConfig.signingKeyKid === undefined) {
      throw new Error('signingKeyKid is missing in client config');
    }

    if (this.clientConfig.signingKeyFileName === undefined) {
      throw new Error('signingKeyFIleName is missing in client config');
    }
    

    const iat = Date.now() / 1000;
    const jwt = {
      header: {
        alg: this.clientConfig.token_endpoint_auth_signing_alg,
        kid: this.clientConfig.signingKeyKid
      },
      body: {
        iss: this.clientConfig.client_id,
        sub: intentID,
        aud: this.wellKnownConfiguration.token_endpoint,
        jti: uuidv4(),
        exp: iat + 30,
        iat
      },
      signingKeyFileName: this.clientConfig.signingKeyFileName
    };

    const jws = await Jwt.sign(jwt);

    // set other http params
    params.fields.assertion = jws; // eslint-disable-line no-param-reassign
  }

  async getAuthorizationCodeUrl(scope, redirectUri, responseType, claims, useRequestObject) {
    // ensure we have the .well-known
    await this.getWellKnownConfiguration();    

    const authorizationEndPoint = this.wellKnownConfiguration.authorization_endpoint;
    if (authorizationEndPoint === undefined) {
      const err = 'Oidc.getAuthorizationCode: authorization_endpoint not defined in well-known config';
      throw new Error(err);
    }

    let url = `${authorizationEndPoint}?`;
    url += await this._getAuthorizationCodeUrlParams(scope, redirectUri, responseType, claims, useRequestObject);

    return url;
  }

  async _getAuthorizationCodeUrlParams(scope, redirectUri, responseType, claims, useRequestObject) {
    let urlParams = `client_id=${this.clientConfig.client_id}`;
    urlParams += `&redirect_uri=${redirectUri}`;
    urlParams += `&response_type=${responseType}`;

    if (useRequestObject) {
      urlParams += '&scope=openid';
      const signedRequestObject = await this._getSignedRequestObject(scope, redirectUri, claims);
      urlParams += `&request=${signedRequestObject}`;
    } else {
      urlParams += `&scope=${scope}`;
      urlParams += `&claims=${claims}`;
    }

    return urlParams;
  }

  async _getSignedRequestObject(scope, redirectUri, claims) {
    const requestObject = {
      aud: this.wellKnownConfiguration.issuer,
      iss: this.clientConfig.client_id,   
      exp: (Date.now() / 1000) + 300,
      state: uuidv4(),   
      nonce: uuidv4(),
      scope,
      redirect_uri: redirectUri,
      claims
    };

    const requestJws = await Jwt.sign({
      header: {
        alg: this.clientConfig.request_object_signing_alg,
        kid: this.clientConfig.signingKeyKid
      },
      body: requestObject,
      signingKeyFileName: this.clientConfig.signingKeyFileName
    });

    return requestJws;
  }
}

module.exports = OidcClient;
