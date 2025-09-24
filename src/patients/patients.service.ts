import {
  Injectable,
  ConflictException,
  BadRequestException,
  Inject,
  Logger,
  InternalServerErrorException,
  NotFoundException,
  ForbiddenException,
  ServiceUnavailableException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';
import * as crypto from 'crypto';


export class PatientService{
  private readonly logger = new Logger(PatientService.name);


  //rate limiting configuration 
  private readonly createRateLimitWindowMs= 60*1000;
  private readonly createMaxRequests= 10;
  private readonly lockTTL = 5 * 1000; 
}