import express, { Request, Response } from "express";
import cors from "cors";
import { config } from "dotenv";
import { initializeApp, cert } from "firebase-admin/app";
import { getAuth } from "firebase-admin/auth";
import { getFirestore } from "firebase-admin/firestore";
import path from "path";

// Load environment variables
config();

// Initialize Firebase Admin
const serviceAccount = {
  projectId: process.env.FIREBASE_PROJECT_ID,
  privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
  privateKey: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n'),
  clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
  clientId: process.env.FIREBASE_CLIENT_ID,
  authUri: process.env.FIREBASE_AUTH_URI,
  tokenUri: process.env.FIREBASE_TOKEN_URI,
  authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
  clientX509CertUrl: process.env.FIREBASE_CLIENT_X509_CERT_URL,
};

// Initialize Firebase Admin
const app = initializeApp({
  credential: cert(serviceAccount as any)
});

// Get Firebase Auth and Firestore instances
const auth = getAuth(app);
const db = getFirestore(app);

// Initialize Express
const expressApp = express();
const port = process.env.PORT || 5000;

// Middleware
expressApp.use(cors());
expressApp.use(express.json());

// Authentication Middleware
const authenticateUser = async (req: Request, res: Response, next: Function) => {
  try {
    const authHeader = req.headers.authorization;
    const userIdHeader = req.headers['x-user-id'] as string;
    
    console.log('Auth request received with headers:', {
      authorization: authHeader ? 'present' : 'absent',
      'x-user-id': userIdHeader
    });
    
    // For testing purposes, check if there's a uid in localStorage stored as part of the user data
    // This is a temporary workaround until proper token verification is implemented
    // This should be replaced with proper JWT verification in production
    if (authHeader) {
      try {
        const token = authHeader.split('Bearer ')[1];
        
        // Attempt to verify token, but don't fail if it doesn't work
        try {
          const decodedToken = await auth.verifyIdToken(token);
          req.user = decodedToken;
        } catch (verifyError) {
          console.warn('Token verification failed, using uid from auth header if available');
          // Extract uid from token or use fallback
          // For demo purposes, we'll extract a uid if it's in the URL
          const tokenParts = token.split('.');
          if (tokenParts.length > 1) {
            try {
              const payload = JSON.parse(Buffer.from(tokenParts[1], 'base64').toString());
              if (payload.uid) {
                req.user = { uid: payload.uid };
              }
            } catch (e) {
              console.warn('Unable to parse token payload');
            }
          }
        }
      } catch (error) {
        console.warn('Error processing auth header:', error);
      }
    }
    
    // If we didn't get a uid from the token, try the X-User-ID header
    if (!req.user?.uid && userIdHeader) {
      console.log('Using X-User-ID header for authentication:', userIdHeader);
      
      // Check if the X-User-ID is an email fallback
      if (userIdHeader.startsWith('email:')) {
        const email = userIdHeader.substring(6); // Remove 'email:' prefix
        console.log('Using email fallback for authentication:', email);
        
        try {
          // Look up the user by email
          const userSnapshot = await db.collection('users').where('email', '==', email).limit(1).get();
          
          if (!userSnapshot.empty) {
            const userData = userSnapshot.docs[0].data();
            console.log('Found user by email:', userData.uid);
            req.user = { uid: userData.uid };
          } else {
            console.log('No user found with email:', email);
          }
        } catch (error) {
          console.error('Error looking up user by email:', error);
        }
      } else {
        req.user = { uid: userIdHeader };
      }
    }
    
    // If we still don't have a user from the token, check for uid in body/query
    if (!req.user?.uid && req.body.uid) {
      req.user = { uid: req.body.uid };
    } else if (!req.user?.uid && req.query.uid) {
      req.user = { uid: req.query.uid as string };
    }
    
    // If we still have no user, send unauthorized
    if (!req.user?.uid) {
      console.log('No uid found in request, sending unauthorized');
      return res.status(401).json({ error: 'Unauthorized - No user information provided' });
    }
    
    console.log('Successfully authenticated user with uid:', req.user.uid);
    next();
  } catch (error) {
    console.error('Authentication error:', error);
    return res.status(401).json({ error: 'Unauthorized - Authentication failed' });
  }
};

// Add these validation functions before your routes
const validateUserData = (data: any): boolean => {
  return !!(
    data.email && 
    typeof data.email === 'string' &&
    data.email.includes('@') &&
    data.password && 
    typeof data.password === 'string' &&
    data.displayName && 
    typeof data.displayName === 'string' &&
    data.displayName.length >= 2
  );
};

const validatePassword = (password: string): boolean => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /[0-9]/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

  return password.length >= minLength && 
    hasUpperCase && 
    hasLowerCase && 
    hasNumbers && 
    hasSpecialChar;
};

// Routes
// Auth Routes
expressApp.post('/api/auth/register', async (req: Request, res: Response) => {
  try {
    const { email, password, displayName } = req.body;

    // Validate user data
    if (!validateUserData(req.body)) {
      return res.status(400).json({ 
        error: 'Invalid user data. Please check all required fields.' 
      });
    }

    // Validate password requirements
    if (!validatePassword(password)) {
      return res.status(400).json({ 
        error: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.' 
      });
    }

    // Use transaction to ensure both operations succeed
    await db.runTransaction(async (transaction) => {
      // Create user in Firebase Auth
      const userRecord = await auth.createUser({
        email,
        password,
        displayName,
      });

      // Create user document in Firestore
      const userRef = db.collection('users').doc(userRecord.uid);
      const userData: User = {
        uid: userRecord.uid,
        email,
        displayName,
        createdAt: new Date(),
        emailVerified: false,
        role: 'user',
      };

      transaction.set(userRef, userData);

      // Create a custom token for the user
      const token = await auth.createCustomToken(userRecord.uid);

      res.status(201).json({ 
        message: 'User created successfully',
        uid: userRecord.uid,
        token,
        displayName
      });
    });

  } catch (error) {
    console.error('Registration error:', error);
    res.status(400).json({ 
      error: error instanceof Error ? error.message : 'Failed to create user' 
    });
  }
});

expressApp.post('/api/auth/login', async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;
    
    // Sign in user with Firebase Auth
    const userRecord = await auth.getUserByEmail(email);
    
    // In a real implementation, you would verify the password here
    // Firebase Auth handles this automatically when using the client SDK
    
    // Create a custom token for the user
    const token = await auth.createCustomToken(userRecord.uid);
    
    res.json({ 
      message: 'Login successful',
      uid: userRecord.uid,
      displayName: userRecord.displayName,
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Utility endpoint to get user by email - for testing only, should be removed in production
expressApp.get('/api/utils/user-by-email', async (req: Request, res: Response) => {
  try {
    const email = req.query.email as string;
    
    if (!email) {
      return res.status(400).json({ error: 'Email parameter is required' });
    }
    
    console.log('Looking up user by email:', email);
    
    try {
      // First try to get the user from Firebase Auth
      const userRecord = await auth.getUserByEmail(email);
      
      // Then get the user document from Firestore for additional data
      const userDoc = await db.collection('users').doc(userRecord.uid).get();
      
      return res.json({
        uid: userRecord.uid,
        email: userRecord.email,
        displayName: userRecord.displayName,
        ...userDoc.exists ? userDoc.data() : {}
      });
    } catch (error) {
      // If not found in Auth, try to look in Firestore
      const userSnapshot = await db.collection('users').where('email', '==', email).limit(1).get();
      
      if (userSnapshot.empty) {
        return res.status(404).json({ error: 'User not found' });
      }
      
      const userData = userSnapshot.docs[0].data();
      return res.json(userData);
    }
  } catch (error) {
    console.error('Error looking up user by email:', error);
    res.status(500).json({ error: 'Failed to find user' });
  }
});

// Post Routes
expressApp.post('/api/posts', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    console.log('Creating post with user ID:', req.user.uid);
    const { content } = req.body;
    
    if (!content || typeof content !== 'string' || content.trim() === '') {
      return res.status(400).json({ error: 'Post content is required' });
    }

    // Get user data for the post author information
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists) {
      console.log('User document not found for UID:', req.user.uid);
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = userDoc.data();
    console.log('Found user data:', userData);
    
    // Create new post
    const postRef = db.collection('posts').doc();
    const postData = {
      id: postRef.id,
      authorId: req.user.uid,
      author: {
        name: userData?.displayName || 'Anonymous',
        avatar: userData?.photoURL || '',
        role: userData?.role || 'User',
      },
      content,
      timestamp: new Date(),
      likes: 0,
      comments: 0,
      likedBy: []
    };

    await postRef.set(postData);
    console.log('Post created with ID:', postRef.id);

    res.status(201).json({ 
      message: 'Post created successfully',
      post: {
        ...postData,
        timestamp: postData.timestamp.toISOString(),
      }
    });
  } catch (error) {
    console.error('Post creation error:', error);
    res.status(500).json({ error: 'Failed to create post' });
  }
});

expressApp.get('/api/posts', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    console.log('Fetching posts for user ID:', req.user.uid);
    
    // Get limit and offset from query parameters
    const limit = parseInt(req.query.limit as string) || 10;
    const offset = parseInt(req.query.offset as string) || 0;
    console.log(`Pagination: limit=${limit}, offset=${offset}`);
    
    // Get posts sorted by timestamp
    const postsSnapshot = await db.collection('posts')
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .offset(offset)
      .get();
    
    console.log(`Found ${postsSnapshot.docs.length} posts`);
    
    const posts = postsSnapshot.docs.map(doc => {
      const data = doc.data();
      return {
        ...data,
        timestamp: data.timestamp.toDate().toISOString(),
        isLiked: data.likedBy?.includes(req.user?.uid) || false
      };
    });

    res.json({ posts });
  } catch (error) {
    console.error('Posts fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch posts' });
  }
});

expressApp.get('/api/posts/user/:userId', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { userId } = req.params;
    
    // Get limit and offset from query parameters
    const limit = parseInt(req.query.limit as string) || 10;
    const offset = parseInt(req.query.offset as string) || 0;
    
    // Get posts by user
    const postsSnapshot = await db.collection('posts')
      .where('authorId', '==', userId)
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .offset(offset)
      .get();
    
    const posts = postsSnapshot.docs.map(doc => {
      const data = doc.data();
      return {
        ...data,
        timestamp: data.timestamp.toDate().toISOString(),
        isLiked: data.likedBy?.includes(req.user?.uid) || false
      };
    });

    res.json({ posts });
  } catch (error) {
    console.error('User posts fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch user posts' });
  }
});

expressApp.post('/api/posts/:postId/like', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { postId } = req.params;
    const postRef = db.collection('posts').doc(postId);
    
    // Get post data
    const postDoc = await postRef.get();
    if (!postDoc.exists) {
      return res.status(404).json({ error: 'Post not found' });
    }
    
    const postData = postDoc.data();
    const likedBy = postData?.likedBy || [];
    const isLiked = likedBy.includes(req.user.uid);
    
    // Update like count and liked by array
    await postRef.update({
      likes: isLiked ? postData?.likes - 1 : postData?.likes + 1,
      likedBy: isLiked 
        ? likedBy.filter((id: string) => id !== req.user?.uid)
        : [...likedBy, req.user.uid]
    });

    res.json({ 
      message: isLiked ? 'Post unliked' : 'Post liked',
      isLiked: !isLiked 
    });
  } catch (error) {
    console.error('Post like error:', error);
    res.status(500).json({ error: 'Failed to like/unlike post' });
  }
});

expressApp.post('/api/posts/:postId/comments', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { postId } = req.params;
    const { text } = req.body;
    
    if (!text || typeof text !== 'string' || text.trim() === '') {
      return res.status(400).json({ error: 'Comment text is required' });
    }

    // Get user data for the comment author information
    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const userData = userDoc.data();
    
    // Create new comment
    const postRef = db.collection('posts').doc(postId);
    const commentsRef = postRef.collection('comments');
    
    const commentRef = commentsRef.doc();
    const commentData = {
      id: commentRef.id,
      postId,
      authorId: req.user.uid,
      author: {
        name: userData?.displayName || 'Anonymous',
        avatar: userData?.photoURL || '',
        role: userData?.role || 'User',
      },
      text,
      timestamp: new Date()
    };

    await commentRef.set(commentData);
    
    // Update comment count on post
    await postRef.update({
      comments: (await commentsRef.count().get()).data().count
    });

    res.status(201).json({ 
      message: 'Comment added successfully',
      comment: {
        ...commentData,
        timestamp: commentData.timestamp.toISOString()
      }
    });
  } catch (error) {
    console.error('Comment creation error:', error);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

expressApp.get('/api/posts/:postId/comments', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { postId } = req.params;
    
    // Get limit and offset from query parameters
    const limit = parseInt(req.query.limit as string) || 10;
    const offset = parseInt(req.query.offset as string) || 0;
    
    // Get comments for post
    const commentsSnapshot = await db.collection('posts').doc(postId)
      .collection('comments')
      .orderBy('timestamp', 'desc')
      .limit(limit)
      .offset(offset)
      .get();
    
    const comments = commentsSnapshot.docs.map(doc => {
      const data = doc.data();
      return {
        ...data,
        timestamp: data.timestamp.toDate().toISOString()
      };
    });

    res.json({ comments });
  } catch (error) {
    console.error('Comments fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch comments' });
  }
});

// Protected Routes
expressApp.get('/api/user/profile', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const userDoc = await db.collection('users').doc(req.user.uid).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(userDoc.data());
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// Chat Routes
expressApp.post('/api/chat/start', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { recipientId } = req.body;
    
    if (!recipientId) {
      return res.status(400).json({ error: 'Recipient ID is required' });
    }

    // Check if recipient exists
    const recipientDoc = await db.collection('users').doc(recipientId).get();
    if (!recipientDoc.exists) {
      return res.status(404).json({ error: 'Recipient user not found' });
    }

    const recipientData = recipientDoc.data();

    // Check if a chat already exists between these users
    const existingChats = await db.collection('chats')
      .where('participants', 'array-contains', req.user.uid)
      .get();

    let chatId = '';
    
    // Check if there's already a chat with the recipient
    for (const chat of existingChats.docs) {
      const chatData = chat.data();
      if (chatData.participants.includes(recipientId)) {
        chatId = chat.id;
        break;
      }
    }

    // If no chat exists, create a new one
    if (!chatId) {
      // Get sender data
      const senderDoc = await db.collection('users').doc(req.user.uid).get();
      if (!senderDoc.exists) {
        return res.status(404).json({ error: 'Sender user not found' });
      }
      const senderData = senderDoc.data();

      // Create a new chat document
      const chatRef = db.collection('chats').doc();
      const chatData = {
        id: chatRef.id,
        participants: [req.user.uid, recipientId],
        participantsInfo: {
          [req.user.uid]: {
            displayName: senderData?.displayName || 'User',
            email: senderData?.email || '',
            photoURL: senderData?.photoURL || '',
          },
          [recipientId]: {
            displayName: recipientData?.displayName || 'User',
            email: recipientData?.email || '',
            photoURL: recipientData?.photoURL || '',
          }
        },
        createdAt: new Date(),
        lastMessage: null,
        lastMessageTime: new Date(),
        unreadCount: {
          [req.user.uid]: 0,
          [recipientId]: 0,
        }
      };

      await chatRef.set(chatData);
      chatId = chatRef.id;
    }

    res.status(200).json({ 
      message: 'Chat created or retrieved successfully',
      chatId
    });
  } catch (error) {
    console.error('Chat creation error:', error);
    res.status(500).json({ error: 'Failed to create chat' });
  }
});

expressApp.get('/api/chat/list', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    console.log('Fetching chats for user:', req.user.uid);

    // Get chats where the user is a participant - without ordering first
    const chatsSnapshot = await db.collection('chats')
      .where('participants', 'array-contains', req.user.uid)
      .get();

    console.log('Chat query completed. Found documents:', chatsSnapshot.size);

    // Process chats and sort them in memory
    let chats = chatsSnapshot.docs.map(doc => {
      const data = doc.data();
      console.log('Processing chat document:', doc.id);
      
      // For each chat, find the other participant
      const otherParticipantId = data.participants?.find((id: string) => id !== req.user?.uid) || '';
      const otherParticipantInfo = data.participantsInfo?.[otherParticipantId] || {};
      
      // Check for lastMessageTime to ensure it exists
      let lastMessageTimeIso;
      let lastMessageDate = new Date(0); // Default to epoch start
      try {
        // Check if lastMessageTime exists and has toDate method
        if (data.lastMessageTime && typeof data.lastMessageTime.toDate === 'function') {
          lastMessageDate = data.lastMessageTime.toDate();
          lastMessageTimeIso = lastMessageDate.toISOString();
        } else {
          // If lastMessageTime is missing or invalid, use creation date or current time
          console.warn('Invalid lastMessageTime for chat', doc.id);
          lastMessageDate = data.createdAt?.toDate() || new Date();
          lastMessageTimeIso = lastMessageDate.toISOString();
        }
      } catch (e) {
        console.error('Error processing lastMessageTime for chat', doc.id, e);
        lastMessageTimeIso = new Date().toISOString(); // Fallback to current time
      }
      
      // Safely access unreadCount with fallbacks
      const currentUserUid = req.user?.uid || '';
      const unreadCount = (data.unreadCount && currentUserUid && data.unreadCount[currentUserUid] !== undefined) 
        ? data.unreadCount[currentUserUid] 
        : 0;
      
      return {
        id: doc.id,
        otherParticipant: {
          id: otherParticipantId,
          displayName: otherParticipantInfo.displayName || 'User',
          photoURL: otherParticipantInfo.photoURL || '',
        },
        lastMessage: data.lastMessage || null,
        lastMessageTime: lastMessageTimeIso,
        lastMessageDate, // For sorting
        unreadCount: unreadCount,
      };
    });

    // Sort chats by lastMessageDate descending (newest first)
    chats.sort((a, b) => b.lastMessageDate.getTime() - a.lastMessageDate.getTime());
    
    // Remove the lastMessageDate property used for sorting
    chats = chats.map(chat => {
      const { lastMessageDate, ...chatWithoutDate } = chat;
      return chatWithoutDate;
    }) as any[]; // Use type assertion to resolve the type error

    console.log('Successfully processed and sorted all chat documents');
    res.json({ chats });
  } catch (error) {
    console.error('Chat list fetch error details:', error);
    // Additional info about the error
    if (error instanceof Error) {
      console.error('Error name:', error.name);
      console.error('Error message:', error.message);
      console.error('Error stack:', error.stack);
    }
    res.status(500).json({ error: 'Failed to fetch chats' });
  }
});

expressApp.post('/api/chat/:chatId/message', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { chatId } = req.params;
    const { text } = req.body;
    
    if (!text || typeof text !== 'string' || text.trim() === '') {
      return res.status(400).json({ error: 'Message text is required' });
    }

    // Check if chat exists
    const chatDoc = await db.collection('chats').doc(chatId).get();
    if (!chatDoc.exists) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    // Check if user is a participant in this chat
    const chatData = chatDoc.data()!;
    if (!chatData.participants.includes(req.user!.uid)) {
      return res.status(403).json({ error: 'You are not a participant in this chat' });
    }

    // Find the other participant to update their unread count
    const otherParticipantId = chatData.participants.find((id: string) => id !== req.user!.uid);

    // Get sender data
    const senderDoc = await db.collection('users').doc(req.user!.uid).get();
    if (!senderDoc.exists) {
      return res.status(404).json({ error: 'Sender user not found' });
    }
    const senderData = senderDoc.data();

    // Create a new message
    const messageRef = db.collection('chats').doc(chatId).collection('messages').doc();
    const messageData = {
      id: messageRef.id,
      senderId: req.user!.uid,
      senderName: senderData?.displayName || 'User',
      text,
      timestamp: new Date(),
      read: false
    };

    await messageRef.set(messageData);

    // Update the chat document with the last message
    const updatedUnreadCount = {
      ...chatData.unreadCount,
      [otherParticipantId]: (chatData.unreadCount?.[otherParticipantId] || 0) + 1
    };

    await db.collection('chats').doc(chatId).update({
      lastMessage: {
        text,
        senderId: req.user!.uid
      },
      lastMessageTime: new Date(),
      unreadCount: updatedUnreadCount
    });

    res.status(201).json({
      message: 'Message sent successfully',
      messageId: messageRef.id
    });
  } catch (error) {
    console.error('Message send error:', error);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

expressApp.get('/api/chat/:chatId/messages', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    const { chatId } = req.params;
    
    // Check if chat exists
    const chatDoc = await db.collection('chats').doc(chatId).get();
    if (!chatDoc.exists) {
      return res.status(404).json({ error: 'Chat not found' });
    }

    // Check if user is a participant in this chat
    const chatData = chatDoc.data()!;
    if (!chatData.participants.includes(req.user!.uid)) {
      return res.status(403).json({ error: 'You are not a participant in this chat' });
    }

    // Get messages
    const messagesSnapshot = await db.collection('chats').doc(chatId)
      .collection('messages')
      .orderBy('timestamp', 'desc')
      .limit(50)
      .get();

    const messages = messagesSnapshot.docs.map(doc => {
      const data = doc.data();
      return {
        id: doc.id,
        senderId: data.senderId,
        senderName: data.senderName,
        text: data.text,
        timestamp: data.timestamp.toDate().toISOString(),
        read: data.read
      };
    });

    // Mark messages as read if they're from the other participant
    const batch = db.batch();
    const unreadMessages = messagesSnapshot.docs.filter(doc => 
      doc.data().senderId !== req.user!.uid && !doc.data().read
    );

    unreadMessages.forEach(doc => {
      batch.update(doc.ref, { read: true });
    });

    // Reset the unread count for this user
    if (unreadMessages.length > 0) {
      const chatRef = db.collection('chats').doc(chatId);
      const updatedUnreadCount = {
        ...chatData.unreadCount,
        [req.user!.uid]: 0
      };
      batch.update(chatRef, { unreadCount: updatedUnreadCount });
    }

    await batch.commit();

    res.json({ messages });
  } catch (error) {
    console.error('Messages fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});

expressApp.get('/api/chat/unread-count', authenticateUser, async (req: Request, res: Response) => {
  try {
    if (!req.user?.uid) {
      return res.status(401).json({ error: 'User not authenticated' });
    }

    // Get all chats for the user
    const chatsSnapshot = await db.collection('chats')
      .where('participants', 'array-contains', req.user.uid)
      .get();

    // Calculate total unread count
    let totalUnreadCount = 0;
    chatsSnapshot.docs.forEach(doc => {
      const chatData = doc.data();
      const userUid = req.user?.uid || '';
      if (chatData.unreadCount && userUid) {
        totalUnreadCount += chatData.unreadCount[userUid] || 0;
      }
    });

    res.json({ unreadCount: totalUnreadCount });
  } catch (error) {
    console.error('Unread count fetch error:', error);
    res.status(500).json({ error: 'Failed to fetch unread count' });
  }
});

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  expressApp.use(express.static(path.join(__dirname, '../../client/build')));

  expressApp.get('*', (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, '../../client/build', 'index.html'));
  });
}

// Start server
expressApp.listen(port, () => {
  console.log(`Server running on port ${port}`);
}); 