import { Injectable,ConflictException,BadRequestException,Inject,Logger,InternalServerErrorException,NotFoundException } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as bcrypt from 'bcrypt';
import { CACHE_MANAGER } from '@nestjs/cache-manager';  
import type { Cache } from 'cache-manager';