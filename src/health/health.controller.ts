import { Controller,Get } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";




@Controller('health')
export class HealthController{
  constructor(private prisma:PrismaService){}

  @Get()
  async check() {
    try {
      await this.prisma.$queryRaw`SELECT 1`; // ping DB
      return {
        status: 'ok',
        database: 'connected',
        timestamp: new Date().toISOString(),
      };
    } catch (e) {
      return {
        status: 'error',
        database: 'disconnected',
        error: e.message,
      };
    }
  }

}
//I dont have much to do here 
