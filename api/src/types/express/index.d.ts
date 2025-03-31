import { DecodedIdToken } from 'firebase-admin/auth';

// Define a custom user type that can be either a DecodedIdToken or have just a uid property
export interface CustomUser {
  uid: string;
  [key: string]: any;
}

declare global {
  namespace Express {
    interface Request {
      user?: DecodedIdToken | CustomUser;
    }
  }
} 