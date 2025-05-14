import { Controller, Logger } from '@nestjs/common';
import { EventPattern, Payload } from '@nestjs/microservices';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';

@Controller()
export class MailConsumer {
  private readonly logger = new Logger(MailConsumer.name);
  private transporter: nodemailer.Transporter;

  constructor(private readonly config: ConfigService) {
    this.transporter = nodemailer.createTransport({
      host: config.get('MAIL_HOST'),
      port: config.get<number>('MAIL_PORT'),
      secure: false,
      auth: {
        user: config.get('MAIL_USER'),
        pass: config.get('MAIL_PASS'),
      },
    });
  }

  @EventPattern('send_email')
  async handleSendEmailMessage(@Payload() payload: any) {
    const { to, token } = payload;

    const verifyUrl = `${this.config.get('APP_URL')}/auth/verify-email?token=${token}`;
    const mailOptions = {
      from: this.config.get('MAIL_FROM'),
      to,
      subject: 'E-posta Doğrulama',
      html: `
        <p>Merhaba,</p>
        <p>Lütfen e-posta adresinizi doğrulamak için aşağıdaki linke tıklayın:</p>
        <a href="${verifyUrl}">${verifyUrl}</a>
        <p>Teşekkürler.</p>
      `,
    };

    await this.transporter.sendMail(mailOptions);
    this.logger.log(`Verification email sent to: ${to}`);
  }
}