interface AuthConfig {
  clientID: string;
  domain: string;
  callbackURL: string;
}

export const AUTH_CONFIG: AuthConfig = {
  clientID: '{CLIENT_ID}',
  domain: 'localhost:4200',
  callbackURL: 'http://localhost:4200/callback'
};
