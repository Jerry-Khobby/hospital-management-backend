import { Module,NestModule,MiddlewareConsumer } from '@nestjs/common';
import { PrescriptionsService } from './prescriptions.service';
import { PrescriptionsController } from './prescriptions.controller';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthMiddleware } from 'src/auth/jwt.strategy';
import { AuthModule } from 'src/auth/auth.module';

@Module({
  imports:[AuthModule],
  controllers: [PrescriptionsController],
  providers: [PrescriptionsService, PrismaService],
})
export class PrescriptionsModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer
      .apply(AuthMiddleware)
      .forRoutes(PrescriptionsController); // ✅ middleware applied to all prescription routes
  }
}