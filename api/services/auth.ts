import { initializeApp } from 'firebase/app';
import { 
  getAuth, 
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  updateProfile
} from 'firebase/auth';
import 'dotenv/config';

const firebaseConfig = {
  apiKey: "AIzaSyDtSEfPL5BAeI2xBHKJazU6qpeybzmWRG8",
  authDomain: "demoproject-6ca40.firebaseapp.com",
  projectId: "demoproject-6ca40",
  storageBucket: "demoproject-6ca40.appspot.com",
  messagingSenderId: "395783418008",
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

export async function signUp(formData: { email: string; password: string; name: string }) {
  try {
    const { email, password, name } = formData;
    
    // Create user with email and password
    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    
    // Update user profile with name
    await updateProfile(userCredential.user, {
      displayName: name
    });

    return { success: true, user: userCredential.user };
  } catch (error: any) {
    console.error('Sign up error:', error);
    return { 
      success: false, 
      error: error.message || 'Failed to create account' 
    };
  }
}

export async function logIn(formData: { email: string; password: string }) {
  try {
    const { email, password } = formData;
    
    // Sign in user with email and password
    const userCredential = await signInWithEmailAndPassword(auth, email, password);
    
    return { success: true, user: userCredential.user };
  } catch (error: any) {
    console.error('Login error:', error);
    return { 
      success: false, 
      error: error.message || 'Failed to sign in' 
    };
  }
}

export async function logOut() {
  try {
    await signOut(auth);
    return { success: true };
  } catch (error: any) {
    console.error('Logout error:', error);
    return { 
      success: false, 
      error: error.message || 'Failed to sign out' 
    };
  }
} 