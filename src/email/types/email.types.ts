export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
}

export interface EmailInfo {
  messageId: string;
}

export interface RateLimitConfig {
  enabled: boolean;
  maxEmailsPerHour?: number;
  maxEmailsPerDay?: number;
}

export interface EmailFromConfig {
  address: string;
  name: string;
}

export interface DeviceInfo {
  browser?: string;
  os?: string;
  ip?: string;
  location?: string;
}

export enum EmailType {
  EMAIL_VERIFICATION = 'email_verification',
  WELCOME = 'welcome',
  PASSWORD_RESET = 'password_reset',
  PASSWORD_CHANGE = 'password_change',
  NEW_DEVICE_LOGIN = 'new_device_login',
  ACCOUNT_LOCKED = 'account_locked',
  SECURITY_ALERT = 'security_alert',
}
