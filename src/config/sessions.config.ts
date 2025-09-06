/**
 * Sessions Configuration
 * Centralized configuration for session management
 */

export const SESSIONS_CONFIG = {
  // Maximum number of active sessions per user
  MAX_SESSIONS_PER_USER: 3,

  // Session timeout in minutes
  SESSION_TIMEOUT_MINUTES: 60,

  // Device trust configuration
  DEVICE_TRUST_IPS: ['127.0.0.1', '::1', 'localhost'] as const,

  DEVICE_TRUST_PREFIXES: [
    '192.168.',
    '10.',
    '172.16.',
    '172.17.',
    '172.18.',
    '172.19.',
    '172.20.',
    '172.21.',
    '172.22.',
    '172.23.',
    '172.24.',
    '172.25.',
    '172.26.',
    '172.27.',
    '172.28.',
    '172.29.',
    '172.30.',
    '172.31.',
  ] as const,

  // Session cleanup interval in minutes
  CLEANUP_INTERVAL_MINUTES: 30,

  // Session inactivity timeout in minutes
  INACTIVITY_TIMEOUT_MINUTES: 15,
} as const;
