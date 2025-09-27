import { Controller, Post, Headers, Body, Logger, Req } from '@nestjs/common';
import { PaymentsService } from './payments.service'; // Hum yeh service bhi banayenge
import { Request } from 'express'; // Agar req object ki zaroorat ho
import { request } from 'http';

@Controller('payments') // Ya 'paypal'
export class PaymentsController {
  private readonly logger = new Logger(PaymentsController.name);

  constructor(private readonly paymentsService: PaymentsService) {}

  @Post('webhook') // Yeh hoga aapka /api/payments/webhook endpoint
  async handlePaypalWebhook(
    @Headers('paypal-transmission-id') transmissionId: string,
    @Headers('paypal-transmission-time') timestamp: string,
    @Headers('paypal-transmission-sig') signature: string,
    @Headers('paypal-cert-url') certUrl: string,
    @Headers('paypal-auth-algo') authAlgo: string,
    @Body() body: any,
     @Req() request: Request // Agar raw body ki zaroorat ho, toh isko uncomment karein
  ) {
    this.logger.log(`Received PayPal Webhook: ${transmissionId}`);
    // console.log('Webhook Body:', body); // Debugging ke liye

    try {
      // Webhook signature verification
      const isVerified = await this.paymentsService.verifyPaypalWebhookSignature(
        transmissionId,
        timestamp,
        signature,
        certUrl,
        authAlgo,
   (request as any).rawBody.toString('utf8') );

      if (!isVerified) {
        this.logger.error('PayPal Webhook: Signature verification failed!');
        return { status: 'failure', message: 'Signature verification failed' };
      }

      this.logger.log('PayPal Webhook: Signature verified successfully!');

      // Process the webhook event
      await this.paymentsService.handlePaypalEvent(body);

      return { status: 'success' };
    } catch (error) {
      this.logger.error('Error processing PayPal webhook:', error.message);
      return { status: 'failure', message: error.message };
    }
  }
}