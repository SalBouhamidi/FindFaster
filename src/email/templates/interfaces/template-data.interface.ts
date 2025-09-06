export interface AccountLockedData {
  fullName: string;
  lockTime: Date;
  reason: string;
  supportEmail: string;
}

export interface PasswordChangeData {
  fullName: string;
  browser: string;
  os: string;
  ip: string;
  timestamp: Date;
}

export interface DeviceInfo {
  browser: string;
  os: string;
  ip: string;
}
