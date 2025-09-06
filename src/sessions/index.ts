export * from './sessions.module';
export * from './controllers/sessions.controller';
export * from './services/session-coordinator.service';
export * from './services/token-invalidator.service';
export * from './repositories/sessions.repository';

// Export schemas and interfaces with explicit naming to avoid conflicts
export {
  Session,
  SessionDocument,
  SessionSchema,
} from './schemas/session.schema';
export {
  DeviceInfo as SessionDeviceInfo,
  SessionInfo,
  SessionManagementResponse,
  CreateSessionDto,
  UpdateSessionDto,
} from './interfaces/session.interface';
