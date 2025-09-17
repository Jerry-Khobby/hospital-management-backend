import { Injectable } from "@nestjs/common";
import { PrismaClient } from "../../generated/prisma";
import { env } from "process";

@Injectable()
export class PrismaService extends PrismaClient{
  constructor(){
    super({
      datasources:{
        db:{
          url:process.env.DATABASE_URL
        }
      }
    })
  }
}