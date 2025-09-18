import { Role } from "generated/prisma";


 export class UserQueryDto{
  page?: number=1;
  limit?: number=10;
  role?:Role;
  isActive?:boolean;
  sortBy?:string='createdAt';
  sortOrder?: 'asc' | 'desc'='desc';
} 