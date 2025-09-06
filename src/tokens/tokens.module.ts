import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { TokenService } from '@/tokens/services/token.service';
import { TokenRepository } from '@/tokens/repositories/tokens.repository';
import { Token, TokenSchema } from '@/tokens/schemas/token.schema';

@Module({
  imports: [
    MongooseModule.forFeature([{ name: Token.name, schema: TokenSchema }]),
  ],
  providers: [TokenService, TokenRepository],
  exports: [TokenService, TokenRepository],
})
export class TokensModule {}
