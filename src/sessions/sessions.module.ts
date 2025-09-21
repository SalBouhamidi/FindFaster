import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Session, SessionSchema } from './schemas/session.schema';
import { SessionsRepository } from './repositories/sessions.repository';
import { SessionCoordinatorService } from './services/session-coordinator.service';
import { TokenInvalidatorService } from './services/token-invalidator.service';
import { SessionExtractorService } from './services/session-extractor.service';
import { SessionsController } from './controllers/sessions.controller';
import { TokensModule } from '../tokens/tokens.module';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Session.name, schema: SessionSchema }]),
    TokensModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('jwt.secret'),
        expiresIn: configService.get<string>('jwt.expiresIn'),
      }),
      inject: [ConfigService],
    }),
  ],
  controllers: [SessionsController],
  providers: [
    SessionsRepository,
    SessionCoordinatorService,
    TokenInvalidatorService,
    SessionExtractorService,
  ],
  exports: [
    SessionsRepository,
    SessionCoordinatorService,
    TokenInvalidatorService,
    SessionExtractorService,
  ],
})
export class SessionsModule {}
