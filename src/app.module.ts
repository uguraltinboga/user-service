// src/app.module.ts
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { ConfigModule } from '@nestjs/config';

import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { User } from './user/user.entity';

import { ClientsModule, Transport } from '@nestjs/microservices';
import { MailService } from './mail/mail.service';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    TypeOrmModule.forRoot({
      type: 'postgres',
      host: process.env.DATABASE_HOST,
      port: parseInt(process.env.DATABASE_PORT || '5432'),
      username: process.env.DATABASE_USER,
      password: process.env.DATABASE_PASSWORD,
      database: process.env.DATABASE_NAME,
      entities: [User],
      synchronize: true, // Geliştirme için OK — Production'da false olmalı
    }),
    AuthModule,
    UserModule,
  ],
})
export class AppModule {}

@Module({
  imports: [
    ClientsModule.register([
      {
        name: 'MAIL_SERVICE', // Servis adı
        transport: Transport.RMQ,
        options: {
          urls: ['amqp://localhost:5672'], // RabbitMQ bağlantısı
          queue: 'email_queue', // Kuyruk adı
          queueOptions: {
            durable: false,
          },
        },
      },
    ]),
  ],
  providers: [MailService],
})
export class MailModule {}