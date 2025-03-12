//tag::top[]
import FusionAuthClient from "@fusionauth/typescript-client";
import express from 'express';
import cookieParser from 'cookie-parser';
import pkceChallenge from 'pkce-challenge';
import { GetPublicKeyOrSecret, verify } from 'jsonwebtoken';
import jwksClient, { RsaSigningKey } from 'jwks-rsa';
import * as path from 'path';

// Add environment variables
import * as dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 8080; // default port to listen

if (!process.env.clientId) {
  console.error('Missing clientId from .env');
  process.exit();
}
if (!process.env.clientSecret) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
if (!process.env.fusionAuthURL) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const fusionAuthURL = process.env.fusionAuthURL;
const fusionAuthRedirectURL = process.env.fusionAuthRedirectURL

// Validate the token signature, make sure it wasn't expired
const validateUser = async (userTokenCookie: { access_token: string }) => {
  // Make sure the user is authenticated.
  if (!userTokenCookie || !userTokenCookie?.access_token) {
    return false;
  }
  try {
    let decodedFromJwt;
    await verify(userTokenCookie.access_token, await getKey, undefined, (err, decoded) => {
      decodedFromJwt = decoded;
    });
    return decodedFromJwt;
  } catch (err) {
    console.error(err);
    return false;
  }
}

const getKey: GetPublicKeyOrSecret = async (header, callback) => {
  const jwks = jwksClient({
    jwksUri: `${fusionAuthURL}/.well-known/jwks.json`
  });
  const key = await jwks.getSigningKey(header.kid) as RsaSigningKey;
  var signingKey = key?.getPublicKey() || key?.rsaPublicKey;
  callback(null, signingKey);
}

//Cookies
const userSession = 'userSession';
const userToken = 'userToken';
const userDetails = 'userDetails'; //Non Http-Only with user info (not trusted)

const client = new FusionAuthClient('33052c8a-c283-4e96-9d2a-eb1215c69f8f-not-for-prod', fusionAuthURL);

// Utils for MFA
const getMF2methodDetails = async (method: string, twoFactor: any) => {
  return twoFactor.methods.find((m: any) => m.method === method);
}

app.use(cookieParser());
/** Decode Form URL Encoded data */
app.use(express.urlencoded());

//end::top[]

// Static Files
//tag::static[]
app.use('/static', express.static(path.join(__dirname, '../static/')));
//end::static[]

//tag::homepage[]
app.get("/", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (await validateUser(userTokenCookie)) {
    res.redirect(302, '/account');
  } else {
    const stateValue = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const pkcePair = await pkceChallenge();
    res.cookie(userSession, { stateValue, verifier: pkcePair.code_verifier, challenge: pkcePair.code_challenge }, { httpOnly: true });

    res.sendFile(path.join(__dirname, '../templates/home.html'));
  }
});
//end::homepage[]

app.get('/login', (req, res, next) => {
  const userSessionCookie = req.cookies[userSession];

  if (!userSessionCookie?.stateValue || !userSessionCookie?.challenge) {
    res.redirect(302, '/');
  }
//tag::login[]
  res.redirect(302, `${fusionAuthURL}/oauth2/authorize?client_id=${clientId}&`+
    `scope=profile%20email%20openid&`+
    `response_type=code&`+
    `redirect_uri=${fusionAuthRedirectURL}/oauth-redirect&`+
    `state=${userSessionCookie?.stateValue}&`+
    `code_challenge=${userSessionCookie?.challenge}&`+
    `code_challenge_method=S256`)
//end::login[]
});

app.get('/oauth-redirect', async (req, res, next) => {
  // Capture query params
  const stateFromFusionAuth = `${req.query?.state}`;
  const authCode = `${req.query?.code}`;

  // Validate cookie state matches FusionAuth's returned state
  const userSessionCookie = req.cookies[userSession];
  if (stateFromFusionAuth !== userSessionCookie?.stateValue) {
    console.log("State doesn't match. uh-oh.");
    console.log("Saw: " + stateFromFusionAuth + ", but expected: " + userSessionCookie?.stateValue);
    res.redirect(302, '/');
    return;
  }

  try {
    // Exchange Auth Code and Verifier for Access Token
//tag::oauth-redirect[]
    const accessToken = (await client.exchangeOAuthCodeForAccessTokenUsingPKCE(authCode,
      clientId,
      clientSecret,
      `${fusionAuthRedirectURL}/oauth-redirect`,
      userSessionCookie.verifier)).response;

    if (!accessToken.access_token) {
      console.error('Failed to get Access Token')
      return;
    }
    res.cookie(userToken, accessToken, { httpOnly: true })
//end::oauth-redirect[]

    // Exchange Access Token for User
    const userResponse = (await client.retrieveUserInfoFromAccessToken(accessToken.access_token)).response;
    if (!userResponse) {
      console.error('Failed to get User from access token, redirecting home.');
      res.redirect(302, '/');
    }
    res.cookie(userDetails, userResponse);

    res.redirect(302, '/account');
  } catch (err: any) {
    console.error(err);
    res.status(err?.statusCode || 500).json(JSON.stringify({
      error: err
    }))
  }
});

//tag::account[]
app.get("/account", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/account.html'));
  }
});
//end::account[]

//tag::make-change[]
app.get("/make-change", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/make-change.html'));
  }
});

app.post("/make-change", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  let error;
  let message;

  var coins = {
    quarters: 0.25,
    dimes: 0.1,
    nickels: 0.05,
    pennies: 0.01,
  };

  try {
    message = 'We can make change for';
    let remainingAmount = +req.body.amount;
    for (const [name, nominal] of Object.entries(coins)) {
      let count = Math.floor(remainingAmount / nominal);
      remainingAmount =
        Math.round((remainingAmount - count * nominal) * 100) / 100;

      message = `${message} ${count} ${name}`;
    }
    `${message}!`;
  } catch (ex: any) {
    error = `There was a problem converting the amount submitted. ${ex.message}`;
  }
  res.json(JSON.stringify({
    error,
    message
  }))

});
//end::make-change[]


//tag::settings[]
app.get("/settings", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];

  if (!userTokenCookie) {
    throw new Error('No user details found in cookie');
  }
  const {userId} = userTokenCookie;
  if (!userId) {
    throw new Error('No user id found in cookie');
  }

  const userResponse = await client.retrieveUser(userId);

  for (const method of ['authenticator', 'email', 'sms']) {
    const mfaMethod = await getMF2methodDetails(method, userResponse.response.user?.twoFactor);
    res.cookie(`${method}-enabled`, !!mfaMethod);
  }

  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/settings.html'));
  }
});
//end::settings[]

//tag::mfa-authenticator[]
app.get('/mfa/authenticator', async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {

    const {userId} = userTokenCookie;
    if (!userId) {
      throw new Error('No user id found in cookie');
    }

    const authenticatorTokens = await client.generateTwoFactorSecret();

    res.cookie('authenticator-secret', authenticatorTokens.response?.secret);
    res.cookie('authenticator-qr-code', authenticatorTokens.response?.secretBase32Encoded);

    res.sendFile(path.join(__dirname, '../templates/authenticator-setup.html'));
  }
});

app.post('/mfa/authenticator', async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  const {userId} = userTokenCookie;
  if (!userId) {
    throw new Error('No user id found in cookie');
  }
});
//end::mfa-authenticator[]

//tag::mfa-verify-authenticator[]
app.post('/mfa/verify-authenticator', async (req, res) => {
  try {
    const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  const {userId} = userTokenCookie;
  if (!userId) {
    throw new Error('No user id found in cookie');
  }

  const {code, secret, qrCodeData} = req.body;
  if (!code) {
    throw new Error('No code provided');
  }

  const verifyResponse = await client.enableTwoFactor(
    userId,
    {
      code,
      method: 'authenticator',
      secret: secret,
      secretBase32Encoded: qrCodeData, 
    }
  )

  res.json(JSON.stringify({
    recoveryCodes: verifyResponse.response.recoveryCodes,
  }))
  } catch (err: any) {
    console.error(err);
    res.status(err?.statusCode || 500).json(JSON.stringify({
      error: err
    }))
  }

});
//end::mfa-verify-authenticator[]

//tag::mfa-verify-email[]
app.get('/mfa/email', async (req, res) => {
  try {
    const userTokenCookie = req.cookies[userToken];

    // Validate user session
    if (!await validateUser(userTokenCookie)) {
      return res.redirect(302, '/');
    }

    // Extract user ID
    const { userId } = userTokenCookie;
    if (!userId) {
      throw new Error('No user ID found in cookie');
    }

    const userResponse = await client.retrieveUser(userId);
    if (!userResponse) {
      throw new Error('Failed to retrieve user');
    }

    // Send the email verification code
    await client.sendTwoFactorCodeForEnableDisable({
      userId,
      email: userResponse?.response.user?.email,
      method: 'email',
    });

    // Send the email-setup.html page
    res.sendFile(path.join(__dirname, '../templates/email-setup.html'));

  } catch (error) {
    const err = error as any;

    // Log more detailed error information
    console.error("Error in /mfa/email:", err.exception.fieldErrors);

    // Return an error response instead of crashing the app
    res.status(500).send("Failed to send email verification code. Please try again.");
  }
});
//end::mfa-verify-email[]

//tag::mfa-verify-email[]
app.post('/mfa/verify-email', async (req, res) => {
  try {
    const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  const {userId} = userTokenCookie;
  if (!userId) {
    throw new Error('No user id found in cookie');
  }

  const {code, email} = req.body;
  if (!code) {
    throw new Error('No code provided');
  }

  // Verifying the code

  const verifyResponse = await client.enableTwoFactor(
    userId,
    {
      code,
      method: 'email',
      email,
    }
  )

  res.json(JSON.stringify({
    code: verifyResponse.response.code,
  }))
  } catch (err: any) {
    console.error("Error in /mfa/sms:", err.exception.fieldErrors);

    res.status(err?.statusCode || 500).json(JSON.stringify({
      error: err
    }))
  }

});
//end::mfa-verify-email[]

//tag::mfa-verify-sms[]
app.get('/mfa/sms', async (req, res) => {
  try {
    const userTokenCookie = req.cookies[userToken];

    // Validate user session
    if (!await validateUser(userTokenCookie)) {
      return res.redirect(302, '/');
    }

    // Extract user ID
    const { userId } = userTokenCookie;
    if (!userId) {
      throw new Error('No user ID found in cookie');
    }

    const userResponse = await client.retrieveUser(userId);
    if (!userResponse) {
      throw new Error('Failed to retrieve user');
    }
    const phoneNumber = userResponse?.response.user?.data?.mobilePhone;

    if (!phoneNumber) {
      return res.status(400).send("No phone number found. Please set a phone number first.");
    }

    // Send the sms verification code
    await client.sendTwoFactorCodeForEnableDisable({
      userId,
      mobilePhone: userResponse?.response.user?.mobilePhone,
      method: 'sms',
    });

    // Send the sms-setup.html page
    res.sendFile(path.join(__dirname, '../templates/sms-setup.html'));

  } catch (error) {
    const err = error as any;

    // Log more detailed error information

    // Return an error response instead of crashing the app
    res.status(500).send("Failed to send sms verification code. Please try again.");
  }
});
//end::mfa-verify-sms[]

//tag::mfa-verify-sms[]
app.post('/mfa/verify-sms', async (req, res) => {
  try {
    const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  const {userId} = userTokenCookie;
  if (!userId) {
    throw new Error('No user id found in cookie');
  }

  const {code, phone} = req.body;
  if (!code) {
    throw new Error('No code provided');
  }

  // Verifying the code

  const verifyResponse = await client.enableTwoFactor(
    userId,
    {
      code,
      method: 'sms',
      mobilePhone: phone,
    }
  )

  res.json(JSON.stringify({
    code: verifyResponse.response.code,
  }))
  } catch (err: any) {
    console.error("Error in /mfa/sms:", err.exception.fieldErrors);
    res.status(err?.statusCode || 500).json(JSON.stringify({
      error: err
    }))
  }

});
//end::mfa-verify-phone[]

//tag::logout[]
app.get('/logout', (req, res, next) => {
  res.redirect(302, `${fusionAuthURL}/oauth2/logout?client_id=${clientId}`);
});
//end::logout[]

//tag::oauth-logout[]
app.get('/oauth2/logout', (req, res, next) => {
  console.log('Logging out...')
  res.clearCookie(userSession);
  res.clearCookie(userToken);
  res.clearCookie(userDetails);

  res.redirect(302, '/')
});
//end::oauth-logout[]

// start the Express server
//tag::app[]
app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});
//end::app[]
