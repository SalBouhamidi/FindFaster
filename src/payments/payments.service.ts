// src/payments/payments.service.ts (Example structure)
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import axios from 'axios'; // For making HTTP requests to PayPal API
// import { UserService } from '../users/users.service'; // Agar user service use karna ho payment status update karne ke liye
import { UsersRepository } from '../users/repositories/users.repository'; // <<-- Import UsersRepository
import { SubscriptionStatus } from '../users/schemas/user.schema';
@Injectable()
export class PaymentsService {
  private readonly logger = new Logger(PaymentsService.name);
  private readonly paypalApiBaseUrl: string;
  private readonly paypalClientId: string;
  private readonly paypalClientSecret: string;
   private readonly paypalWebhookId: string;

  constructor(
    private configService: ConfigService,
    private usersRepository: UsersRepository,
    // private userService: UserService, // Inject User service here if needed
  ) {
    this.paypalApiBaseUrl = this.configService.get<string>('PAYPAL_API_BASE_URL') || 'https://api-m.sandbox.paypal.com'; // Ya live URL
    this.paypalClientId = this.configService.get<string>('PAYPAL_CLIENT_ID') || '';
    this.paypalClientSecret = this.configService.get<string>('PAYPAL_CLIENT_SECRET' ) || '';
        this.paypalWebhookId = this.configService.get<string>('PAYPAL_WEBHOOK_ID')  || ''; // <<-- Webhook ID get karein


    if (!this.paypalClientId || !this.paypalClientSecret) {
      this.logger.error('PayPal Client ID or Secret is missing in configuration.');
      throw new Error('PayPal API credentials are not configured.');
    }
  }

  // PayPal API se Access Token hasil karna
  private async getPaypalAccessToken(): Promise<string> {
    try {
      const auth = Buffer.from(`${this.paypalClientId}:${this.paypalClientSecret}`).toString('base64');
      const response = await axios.post(
        `${this.paypalApiBaseUrl}/v1/oauth2/token`,
        'grant_type=client_credentials',
        {
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': `Basic ${auth}`,
          },
        },
      );
      return response.data.access_token;
    } catch (error) {
      this.logger.error('Failed to get PayPal Access Token:', error.message);
      throw new Error('Failed to get PayPal Access Token.');
    }
  }

  // PayPal Webhook Signature Verify karna
  async verifyPaypalWebhookSignature(
    transmissionId: string,
    timestamp: string,
    signature: string,
    certUrl: string,
    authAlgo: string,
    webhookEvent: any, // Raw body ya parsed body
  ): Promise<boolean> {
    try {
      const accessToken = await this.getPaypalAccessToken();
      const response = await axios.post(
        `${this.paypalApiBaseUrl}/v1/notifications/verify-webhook-signature`,
        {
          auth_algo: authAlgo,
          cert_url: certUrl,
          transmission_id: transmissionId,
          transmission_sig: signature,
          transmission_time: timestamp,
          webhook_id: this.configService.get<string>('PAYPAL_WEBHOOK_ID'), // Aapko yeh ID PayPal dashboard se leni hogi
          // The webhookEvent should be the *raw* body string for verification.
          // If you're using @Body(), you might need to get rawBody from Express's req object.
          webhook_event: webhookEvent // Usually this is the parsed JSON body
        },
        {
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${accessToken}`,
          },
        },
      );
      return response.data.verification_status === 'SUCCESS';
    } catch (error) {
      this.logger.error('Error verifying PayPal webhook signature:', error.message);
      return false;
    }
  }

  // PayPal Event handle karna
    async handlePaypalEvent(event: any): Promise<void> {
    this.logger.log(`Handling PayPal Event: ${event.event_type}`);

    switch (event.event_type) {
      case 'PAYMENT.CAPTURE.COMPLETED':
        const transactionId = event.resource.id;
        const payerEmail = event.resource.payer.email_address;
        const paymentStatus = event.resource.status; // Should be 'COMPLETED'
        const grossAmount = event.resource.amount.value;
        const currency = event.resource.amount.currency_code;
        const updateTime = new Date(event.resource.update_time);

        if (paymentStatus === 'COMPLETED') {
          this.logger.log(`Processing completed payment for ${payerEmail} (Txn: ${transactionId})`);

          const user = await this.usersRepository.findByEmail(payerEmail);

          if (user) {
            user.isPremium = true;
            user.subscriptionStatus = SubscriptionStatus.ACTIVE;
            user.lastPaymentDate = updateTime;
            user.paymentAmount = parseFloat(grossAmount);
            user.paymentCurrency = currency;
            user.hotmartTransactionId = transactionId; // PayPal Txn ID ko yahan store kar rahe hain
            // Example: 1 saal ka subscription - client ke business logic ke mutabiq adjust karein
            user.subscriptionExpiryDate = new Date(updateTime.getFullYear() + 1, updateTime.getMonth(), updateTime.getDate());

            await user.save();
            this.logger.log(`User ${payerEmail} (ID: ${user.id}) updated to premium status.`);
          } else {
            this.logger.warn(`User with email ${payerEmail} not found for payment update. Txn ID: ${transactionId}`);
            // Agar user nahi milta, toh yahan koi aur handling logic add kar sakte hain.
            // Maslan, is payment ko record kar ke admin ko notification bhej sakte hain.
          }
        } else {
          this.logger.warn(`Payment capture not completed for ${payerEmail}. Status: ${paymentStatus}`);
        }
        break;

      case 'CHECKOUT.ORDER.APPROVED':
        this.logger.log(`Checkout order approved: ${event.resource.id}`);
        // Agar aap checkout.order flow use kar rahe hain, toh yahan bhi user update logic add kar sakte hain
        break;

      case 'CUSTOMER.SUBSCRIPTION.ACTIVATED': // Agar subscriptions use ho rahi hain
        this.logger.log(`Subscription activated: ${event.resource.id} for user ${event.resource.subscriber.email_address}`);
        // Handle subscription activation logic
        break;

      case 'CUSTOMER.SUBSCRIPTION.CANCELLED': // Subscription cancel hone par
        this.logger.log(`Subscription cancelled: ${event.resource.id} for user ${event.resource.subscriber.email_address}`);
        // User ki subscription status update karein to INACTIVE/CANCELLED
        // const canceledUser = await this.usersRepository.findByEmail(event.resource.subscriber.email_address);
        // if (canceledUser) {
        //   canceledUser.isPremium = false;
        //   canceledUser.subscriptionStatus = SubscriptionStatus.CANCELLED;
        //   await canceledUser.save();
        // }
        break;

      default:
        this.logger.warn(`Unhandled PayPal event type: ${event.event_type}`);
    }
  }
}
