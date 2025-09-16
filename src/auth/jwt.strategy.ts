import {Injectable,NestMiddleware,UnauthorizedException} from '@nestjs/common';
import {Request,Response,NextFunction} from 'express';
import { AuthService } from './auth.service';

@Injectable()
export class AuthMiddleware implements NestMiddleware{
  constructor(private authService:AuthService){}

  async use(req:Request,res:Response,next:NextFunction){
    const authHeader = req.headers['authorization'];
    if(!authHeader){
      throw new UnauthorizedException('Authorization header missing');
    }
    const token = authHeader.split(' ')[1];
    if(!token){
      throw new UnauthorizedException('Token missing');
    }
    try{
      const payload = await this.authService.validateToken(token);
      (req as any).userId = payload.userId;
      next();
    }catch{
      throw new UnauthorizedException('Invalid or expired token');
    }
  }
}