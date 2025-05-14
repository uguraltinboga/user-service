import { Module } from '@nestjs/common';
import { MailService } from './mail.service';
import { MailConsumer } from './mail.consumer';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { ConfigModule, ConfigService } from '@nestjs/config';

@Module({
  imports: [
    ConfigModule,
    ClientsModule.registerAsync([
      {
        name: 'MAIL_SERVICE',
        useFactory: async (configService: ConfigService) => {
          const rabbitmqUrl = configService.get('RABBITMQ_URL');
          if (!rabbitmqUrl) {
            throw new Error('RabbitMQ URL is not configured!');
          }
          return {
            transport: Transport.RMQ,
            options: {
              urls: [rabbitmqUrl],
              queue: 'mail_queue',
              queueOptions: {
                durable: false,
              },
            },
          };
        },
        inject: [ConfigService],
      },
    ]),
  ],
  providers: [MailService],
  controllers: [MailConsumer],
  exports: [MailService],
})
export class MailModule {}