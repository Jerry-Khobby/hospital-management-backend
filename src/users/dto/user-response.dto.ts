import { User, Role } from 'generated/prisma';

export class UserResponseDto {
  id: number;
  email: string;
  name: string;
  role: Role;
  createdAt: Date;

  constructor(user: User) {
    this.id = user.id;
    this.email = user.email;
    this.name = user.name;
    this.role = user.role;
    this.createdAt = user.createdAt;
  }
}
