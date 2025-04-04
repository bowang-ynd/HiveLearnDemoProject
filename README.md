# HiveLearn

A modern web application for collaborative learning and content sharing with built-in chat functionality.

## Features

- User Authentication with Firebase (signup, login, profile management)
- Post Creation and Interaction (like, comment)
- Real-time Chat Messaging
- User Profiles with Social Interaction
- Responsive Design for Mobile and Desktop

## Tech Stack

- **Frontend**: React + TypeScript, Tailwind CSS
- **Backend**: Express.js + TypeScript
- **Database & Authentication**: Firebase Firestore, Firebase Auth
- **Deployment**: Can be deployed on Vercel, Netlify, or any Node.js hosting service

## Prerequisites

- Node.js (v14 or higher)
- npm or yarn
- Firebase account and project

## Installation and Setup

### Step 1: Clone the Repository

```bash
git clone https://github.com/yourusername/hivelearn.git
cd hivelearn
```

### Step 2: Firebase Setup

1. Create a Firebase project at [Firebase Console](https://console.firebase.google.com/)
2. Enable Firebase Authentication (Email/Password)
3. Create a Firestore database in test mode
4. Generate Firebase Admin SDK credentials:
   - Go to Project Settings > Service Accounts
   - Click "Generate new private key"
   - Save the JSON file securely

### Step 3: Backend Setup

1. Navigate to the API directory:
   ```bash
   cd api
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the api directory with your Firebase Admin SDK configuration:
   ```
   PORT=5000
   FIREBASE_PROJECT_ID=your-project-id
   FIREBASE_PRIVATE_KEY_ID=your-private-key-id
   FIREBASE_PRIVATE_KEY="your-private-key" # Make sure to include quotes to preserve newlines
   FIREBASE_CLIENT_EMAIL=your-client-email
   FIREBASE_CLIENT_ID=your-client-id
   FIREBASE_AUTH_URI=https://accounts.google.com/o/oauth2/auth
   FIREBASE_TOKEN_URI=https://oauth2.googleapis.com/token
   FIREBASE_AUTH_PROVIDER_X509_CERT_URL=https://www.googleapis.com/oauth2/v1/certs
   FIREBASE_CLIENT_X509_CERT_URL=your-client-cert-url
   ```
   Note: Copy these values from your Firebase Admin SDK JSON file.

### Step 4: Frontend Setup

1. Navigate to the client directory:
   ```bash
   cd ../client
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a `.env` file in the client directory:
   ```
   REACT_APP_API_URL=http://localhost:5000
   ```

## Running the Application

### Start the Backend Server

```bash
cd api
npm run dev
```

The server will start on http://localhost:5000.

### Start the Frontend Application

```bash
cd client
npm start
```

The application will open in your browser at http://localhost:3000.

## Using the Application

1. **Register an Account**: Navigate to /signup to create a new account
2. **Login**: Use your credentials to log in at /signin
3. **Explore the Feed**: View and interact with posts on the home page
4. **Create Content**: Create new posts from your profile page
5. **Chat**: Start conversations with other users by clicking the chat button on their posts
6. **Check Messages**: View your messages using the messages dropdown in the header

## Firestore Collections Structure

The application uses the following Firestore collections:

- **users**: User profile information
- **posts**: User-created content
- **comments**: Comments on posts
- **likes**: Records of post likes
- **chats**: Chat conversations between users

## Troubleshooting

- **Firebase Errors**: Verify your Firebase configuration in the .env files
- **CORS Issues**: The backend has CORS enabled for localhost:3000 by default
#
