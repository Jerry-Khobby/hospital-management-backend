import { Module } from "@nestjs/common";

import { UserService } from "./users.service";
import { UsersController } from "./users.controller";
import { PrismaService } from "src/prisma/prisma.service";
import { ConfigModule } from "@nestjs/config";
@Module({
  imports: [ConfigModule],
  providers: [UserService, PrismaService],
  exports: [UserService],
  controllers: [UsersController],
})

export class UsersModule {}