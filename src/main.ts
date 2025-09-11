import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule,DocumentBuilder } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  //create swagger config 
  const config = new DocumentBuilder()
  .setTitle('Hospital Management API')
  .setDescription('The Hospital Management API description')
  .addTag('hospital-management')
  .setVersion('1.0')
  .build();
  const document =()=> SwaggerModule.createDocument(app,config);
  SwaggerModule.setup('api',app,document);
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
