import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EmailService } from './services/email.service';
import { EmailTemplates } from './templates/email-templates.service';
import { EmailTemplateRepository } from './repositories/email-template.repository';

@Module({
  imports: [ConfigModule],
  providers: [EmailService, EmailTemplates, EmailTemplateRepository],
  exports: [EmailService],
})
export class EmailModule {}
