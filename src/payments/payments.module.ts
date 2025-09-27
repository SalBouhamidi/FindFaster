import { Module } from '@nestjs/common';
import { PaymentsController } from './payments.controller';
import { PaymentsService } from './payments.service';
import { ConfigModule } from '@nestjs/config'; // ConfigService use karne ke liye
import { UsersModule } from '../users/users.module'; // Agar PaymentsService mein UsersService use ho rahi hai

@Module({
  imports: [ConfigModule, UsersModule,], // Agar PaymentsService mein ConfigService use ho rahi hai
  controllers: [PaymentsController],
  providers: [PaymentsService],
    exports: [PaymentsService] 
})
export class PaymentsModule {}