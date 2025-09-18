import { 
  Injectable, 
  UnauthorizedException, 
  ConflictException, 
  BadRequestException,
  Inject,
  Logger 
} from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as bcrypt from 'bcrypt';
import * as jwt from 'jsonwebtoken';
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import type { Cache } from 'cache-manager';


@Injectable()
export class UserService {
  private readonly logger = new Logger(UserService.name);
  private readonly CACHE_TTL = 300; // 5 minutes in seconds
  private readonly USERS_CACHE_KEY = 'all_users';

  constructor(
    private prisma: PrismaService,
    @Inject(CACHE_MANAGER) private cacheManager: Cache
  ) {}

  async findAllUsers() {
    // Try to get users from cache first
    const cachedUsers = await this.cacheManager.get<any[]>(this.USERS_CACHE_KEY);
    
    if (cachedUsers) {
      this.logger.log('Returning users from cache');
      return cachedUsers;
    }

    this.logger.log('Cache miss - fetching users from database');
    
    // If not in cache, fetch from database
    const users = await this.prisma.user.findMany();
    
    // Store in cache for future requests
    await this.cacheManager.set(this.USERS_CACHE_KEY, users, this.CACHE_TTL * 1000);
    
    return users;
  }


//I want to get user by id with caching 
  async findUserById(id:number){
    const cachedUser = await this.cacheManager.get<any[]>(`user:${id}`);
    if(cachedUser){
      this.logger.log(`Returning user ${id} from cache`);
      return cachedUser;
    }
    const user = await this.prisma.user.findUnique({where:{id}})
    if(!user){
      throw new BadRequestException('User not found');
    }
    await this.cacheManager.set(`user:${id}`,user,this.CACHE_TTL*1000);
    return user;
  }
}