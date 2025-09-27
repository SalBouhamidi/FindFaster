import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
//import { EmailModule } from './email/email.module';
import { TokensModule } from './tokens/tokens.module';
import { RolesModule } from './roles/roles.module';
import { SessionsModule } from './sessions/sessions.module';
import configuration from './config/configuration';
import emailConfig from './config/email.config';
import { DatabaseModule } from './database/database.module';
import { PaymentsModule } from './payments/payments.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: ['.env'],
      expandVariables: true,
      cache: true,
      load: [configuration],   //, emailConfig
    }),
    DatabaseModule,
    AuthModule,
    UsersModule,
    //EmailModule,
    TokensModule,
    RolesModule,
    SessionsModule,
    PaymentsModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
