import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { Transport, MicroserviceOptions } from '@nestjs/microservices';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // RabbitMQ mikroservisini başlatıyoruz
  app.connectMicroservice<MicroserviceOptions>({
    transport: Transport.RMQ,
    options: {
      urls: [process.env.RABBITMQ_URL || 'amqp://localhost'], // RabbitMQ URL'nizi buraya ekleyin
      queue: 'mail_queue', // Mail kuyruğu
      queueOptions: {
        durable: false, // Kuyruk kalıcılığı
      },
    },
  });

  await app.startAllMicroservices(); // Mikroservislerin başlatılmasını sağlıyor
  await app.listen(process.env.PORT ?? 3000); // HTTP sunucusunun başlatılması
}
bootstrap();