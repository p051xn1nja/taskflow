import type { NextAuthOptions } from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import { compare } from 'bcryptjs'
import { getDb } from './db'

declare module 'next-auth' {
  interface Session {
    user: {
      id: string
      username: string
      email: string
      display_name: string
      role: 'admin' | 'user'
      profile_photo: string
    }
  }
  interface User {
    id: string
    username: string
    email: string
    display_name: string
    role: 'admin' | 'user'
    profile_photo: string
  }
}

declare module 'next-auth/jwt' {
  interface JWT {
    id: string
    username: string
    role: 'admin' | 'user'
    display_name: string
    profile_photo: string
  }
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        username: { label: 'Username', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials) {
        if (!credentials?.username || !credentials?.password) return null

        const db = getDb()
        const user = db
          .prepare(
            'SELECT id, username, email, password_hash, display_name, role, is_active, profile_photo FROM users WHERE username = ?'
          )
          .get(credentials.username) as {
          id: string
          username: string
          email: string
          password_hash: string
          display_name: string
          role: 'admin' | 'user'
          is_active: number
          profile_photo: string
        } | undefined

        if (!user || !user.is_active) return null

        const valid = await compare(credentials.password, user.password_hash)
        if (!valid) return null

        return {
          id: user.id,
          username: user.username,
          email: user.email,
          display_name: user.display_name,
          role: user.role,
          profile_photo: user.profile_photo || '',
        }
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        token.id = user.id
        token.username = user.username
        token.role = user.role
        token.display_name = user.display_name
        token.profile_photo = user.profile_photo || ''
      }
      return token
    },
    async session({ session, token }) {
      session.user = {
        id: token.id,
        username: token.username,
        email: token.email as string,
        display_name: token.display_name,
        role: token.role,
        profile_photo: token.profile_photo || '',
      }
      return session
    },
  },
  pages: {
    signIn: '/login',
  },
  session: {
    strategy: 'jwt',
    maxAge: 24 * 60 * 60,
  },
  secret: process.env.NEXTAUTH_SECRET || 'dev-only-secret-not-for-production',
}
