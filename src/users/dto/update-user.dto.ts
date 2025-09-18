import { Role } from "generated/prisma";


export class UpdateUserDto{
  email?: string;
  name?: string;
  password?: string;
  role?: Role;
}