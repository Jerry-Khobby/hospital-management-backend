import {Module} from '@nestjs/common';
import { PatientService } from './patients.service';
import { PatientController } from './patients.controller';
import { PrismaService } from 'src/prisma/prisma.service';
import { ConfigModule } from '@nestjs/config';
import { CacheModule } from '@nestjs/cache-manager';


@Module({
  imports: [ConfigModule,CacheModule.register({
    ttl:300,
    max:1000,
  })],
  providers: [PatientService, PrismaService],
  exports: [PatientService],
  controllers: [PatientController],
})


export class PatientsModule {}