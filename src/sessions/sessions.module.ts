import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { Session, SessionSchema } from '@sessions/schemas/session.schema';
import { SessionsRepository } from '@sessions/repositories/sessions.repository';
import { SessionCoordinatorService } from '@sessions/services/session-coordinator.service';
import { TokenInvalidatorService } from '@sessions/services/token-invalidator.service';
import { SessionExtractorService } from '@sessions/services/session-extractor.service';
import { SessionsController } from '@sessions/controllers/sessions.controller';
import { TokensModule } from '@tokens/tokens.module';

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
