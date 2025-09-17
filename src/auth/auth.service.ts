import { Injectable,UnauthorizedException } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import * as bcrypt from 'bcrypt'
import * as jwt from 'jsonwebtoken'



@Injectable()
export class AuthService{
private readonly jwtSecret = process.env.SECRET_KEY;

constructor(private prisma:PrismaService){}

async hashPassword(password:string):Promise<string>{
  const salt = await bcrypt.genSalt();
  return bcrypt.hash(password,salt);
}

async generateToken(userId:number):Promise<string>{
  return jwt.sign({userId},this.jwtSecret,{expiresIn:'1h'});
}
async register(name:string,email:string,password:string,role:'ADMIN'|'DOCTOR'|'NURSE'|'PATIENT'|'PHARMACIST'):Promise<{token:String}>{
const hashedPassword = await this.hashPassword(password);
const user = await this.prisma.user.create({
  data:{email,password:hashedPassword,name,role}
})
const token = await this.generateToken(user.id)
  return {token};
}

//creating the function for login  with email, password and role 
async login(email:string,password:string,role: 'ADMIN' | 'DOCTOR' | 'NURSE' | 'PATIENT' | 'PHARMACIST'):Promise<{token:String}>{
  const user = await this.prisma.user.findUnique({where:{email}});
  if(!user || user.role !== role){
    throw new UnauthorizedException('Invalid credentials');
  }
  const isPasswordValid = await bcrypt.compare(password,user.password);
  if(!isPasswordValid){
    throw new UnauthorizedException('Invalid credentials');
  }
  const token = await this.generateToken(user.id);
  return {token};
}

//async validateToken
async validateToken(token:string):Promise<{userId:number}>{
  try{
    const decoded = jwt.verify(token,this.jwtSecret) as {userId:number};
    return {userId:decoded.userId};
  }catch{
    throw new UnauthorizedException('Invalid token or expired token');
  }
}



}