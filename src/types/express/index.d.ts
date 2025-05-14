import { User } from '../../user/entities/user.entity';

declare module 'express' {
  export interface Request {
    user?: User;
  }
}
