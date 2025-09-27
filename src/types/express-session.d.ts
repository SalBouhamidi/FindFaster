import 'express-session';
declare module 'express-session' {
  interface SessionData {
    authPreferences?: {
      termsAccepted: boolean;
      subscribeUpdates: boolean;
    };
  }
}

declare namespace Express {
  interface Request {
    rawBody?: Buffer; 
  }
}