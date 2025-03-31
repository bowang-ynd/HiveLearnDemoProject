interface User {
  uid: string;
  email: string;
  displayName: string;
  createdAt: Date;
  emailVerified: boolean;
  bio?: string;
  avatar?: string;
  interests?: string[];
  role: 'user' | 'admin';
  lastLogin?: Date;
}
