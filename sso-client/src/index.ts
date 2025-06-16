/**
 * @file Server application to authenticate and manage user sessions using SSO
 * @module index
 * @license MIT Licensed 2025
 *
 * @description
 * This application acts as a **confidential OpenID Connect (OIDC) client** for the
 * **BC Government's Common Keycloak service**. It implements the **Authorization Code Flow**
 * to securely authenticate users and manage their sessions.
 *
 * All incoming requests are routed via an **NGINX reverse proxy**, which handles SSL/TLS termination
 * and potentially load balancing. User session data is externalized and managed using **Redis**
 * as a high-performance session store, enabling statelessness and horizontal scalability for
 * the Node.js application instances.
 *
 * This setup ensures robust security, seamless Single Sign-On (SSO) with other
 * BC Government applications, and efficient resource management.
 *
 * @see {@link https://openid.net/specs/openid-connect-core-1_0.html|OpenID Connect Core 1.0}
 * @see {@link https://www.keycloak.org/|Keycloak Official Website}
 * @see {@link https://nginx.org/|NGINX Official Website}
 * @see {@link https://redis.io/|Redis Official Website}
 *
 * @version 1.0.0
 * @author Government of British Columbia
 */

import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import morgan from 'morgan';
import session from 'express-session';
import passport from 'passport';
import { Issuer, Strategy, TokenSet, Client } from 'openid-client';
import * as redis from 'redis'; // Correct import for Redis v4+ client
import {RedisStore} from "connect-redis"; 
import cookieParser from "cookie-parser";
import config from './config.js';

// Extend the session type for TypeScript to recognize custom properties
declare module 'express-session' {
  interface SessionData {
    redirectURL?: string;
  }
}

// FIX: TS2717: Subsequent property declarations must have the same type.
// Remove `user?: any` here, as Passport's types for `req.user` should handle it.
// If you need a specific type for `req.user`, you should extend Passport's User type.
declare global {
  namespace Express {
    interface Request {
      // user?: any; // REMOVE THIS LINE
      isAuthenticated(): boolean;
    }
  }
}

// Application port
if (!config) {
  throw new Error("Config is undefined. Please ensure the configuration is loaded properly.");
}
const port = Number(config.SSO_CLIENT_PORT);

let keycloakIssuer: Issuer;
let keycloakClient: Client;

(async () => {
  try {
    keycloakIssuer = await Issuer.discover(
      `${config.SSO_AUTH_SERVER_URL}/auth/realms/${config.SSO_REALM}/.well-known/openid-configuration`,
    );

    keycloakClient = new keycloakIssuer.Client({
      client_id: config.SSO_CLIENT_ID,
      client_secret: config.SSO_CLIENT_SECRET,
      redirect_uris: [config.SSO_REDIRECT_URL],
      response_types: ['code'],
    });

    // Initialize Redis client for session store
    const redisClient = redis.createClient({
      url: config.SSO_REDIS_SESSION_STORE_URL,
      password: config.SSO_REDIS_CONNECT_PASSWORD || undefined
    });

    redisClient.on('error', (err: Error) => {
      console.error('Could not establish a connection with redis. ' + err.message);
    });
    redisClient.on('connect', () => {
      console.log('Connected to redis session store successfully');
    });

    // Connect to Redis
    await redisClient.connect();


    // FIX: TS2322: Type 'string | undefined' is not assignable to type 'string'.
    // Ensure all elements in allowedOrigins are strings.
    const allowedOrigins: string[] = [
      config.HOSTNAME,
      config.NGINX_PROXY_URL,
      config.SSO_CLIENT_HOST,
      config.SSO_AUTH_SERVER_URL,
      config.SSO_REDIS_SESSION_STORE_URL
    ];

    const corsConfig: cors.CorsOptions = {
      origin: allowedOrigins,
      methods: ["GET", "POST"],
      credentials: true,
      optionsSuccessStatus: 200,
    };

    const app = express();

    app.use(cors(corsConfig));
    app.use(helmet());
    app.use(morgan(':method :url :status :res[content-length] - :response-time ms'));
    app.use(express.json());
    app.use(express.urlencoded({ extended: true }));
    app.disable("x-powered-by");
    app.set("trust proxy", 1);

    // FIX: TS7009 & TS2353 for RedisStore and TS2322 for secret
    // connect-redis v7.x expects a 'client' property.
    // Ensure `secret` is a string.
    app.use(session({
      store: new RedisStore({ client: redisClient }), // Use 'new' keyword for RedisStore
      secret: config.SSO_SESSION_SECRET, // Now definitely a string from config
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: true,
        maxAge: 1000 * 60 * 60 * 24,
        sameSite: 'none', // Required for secure: true across different domains if not same-site
      }
    }));
    app.use(cookieParser(config.SSO_SESSION_SECRET)); // Also a string here

    app.use(passport.initialize());
    app.use(passport.session());

    let tokenset: TokenSet = {} as TokenSet;

    passport.use(
      'oidc',
      new Strategy({ client: keycloakClient }, (tokenSet: TokenSet, userinfo: any, done: (err: any, user?: any, info?: any) => void) => { // FIX: TS7006: Type `done`
        tokenset = tokenSet;
        return done(null, tokenSet.claims());
      }),
    );
    passport.serializeUser((user: any, done: (err: any, id?: any) => void) => { // Type done
      done(null, user);
    });
    passport.deserializeUser((user: any, done: (err: any, user?: any) => void) => { // Type done
      done(null, user);
    });

    app.get('/authn', (req: Request, res: Response, next: NextFunction) => {
      const redirectURL = req.query.relay as string || '/';
      req.session.redirectURL = redirectURL;
      passport.authenticate('oidc')(req, res, next);
    });

    app.get('/authn/callback', (req: Request, res: Response, next: NextFunction) => {
      passport.authenticate('oidc', {
        successRedirect: `https://${req.headers.host}${req.session.redirectURL || '/'}`,
        failureRedirect: '/',
      })(req, res, next);
    });

    app.get('/health', (req: Request, res: Response) => {
      return res.sendStatus(200);
    });

    app.get('/logout', (req: Request, res: Response, next: NextFunction) => {
      req.session.destroy((err) => {
        if (err) {
          console.error("Error destroying session:", err);
          return next(err);
        }

        const idToken = tokenset.id_token;
        if (!idToken) {
          console.warn("No ID Token found for logout redirection. Redirecting to default.");
          return res.redirect(`${config!.SM_LOGOUT_URL}?retnow=1&returl=${encodeURIComponent(config!.SSO_LOGOUT_REDIRECT_URI)}`);
        }

        const retUrl = `${config!.SSO_AUTH_SERVER_URL}/auth/realms/${config!.SSO_REALM
          }/protocol/openid-connect/logout?post_logout_redirect_uri=${encodeURIComponent(
            config!.SSO_LOGOUT_REDIRECT_URI, // Now correctly defined in config
          )}&id_token_hint=${idToken}`;

        res.redirect(`${config!.SM_LOGOUT_URL}?retnow=1&returl=${encodeURIComponent(retUrl)}`);
      });
    });

    app.get('/', (req: Request, res: Response) => {
      return res.sendStatus(req.isAuthenticated() ? 200 : 401);
    });

    app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
      console.error(err);
      res.status(500).send({ error: 'Internal Server Error' });
    });

    app.use((req: Request, res: Response, next: NextFunction) => {
      res.status(404).send({ error: 'Not Found' });
    });

    app.listen(port, () => {
      console.log(`Server listening on port ${port}`);
      console.log(`Client host at ${config?.HOSTNAME}`); // Now correctly defined in config
    });

  } catch (error) {
    console.error('Failed to discover Keycloak Issuer or connect to Redis:', error);
    process.exit(1);
  }
})();