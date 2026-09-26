'use client'

import { useState } from 'react'
import { supabase, isSupabaseConfigured } from '@/lib/supabase'
import { Shield, Lock, Mail, User, ArrowRight, CheckCircle2, AlertCircle, ExternalLink } from 'lucide-react'
import type { User as SupabaseUser } from '@supabase/supabase-js'

interface AuthScreenProps {
  onAuthenticated: (user: SupabaseUser) => void
}

export function AuthScreen({ onAuthenticated }: AuthScreenProps) {
  const [isSignUp, setIsSignUp] = useState(false)
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [errorMsg, setErrorMsg] = useState<string | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)

  const handleAuth = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrorMsg(null)
    setSuccessMsg(null)

    if (!email || !password) {
      setErrorMsg('Please provide both email and password.')
      return
    }

    if (isSignUp && !username.trim()) {
      setErrorMsg('Please enter a username.')
      return
    }

    if (!isSupabaseConfigured) {
      // Demo fallback when Supabase keys are not set up in .env.local yet
      const mockUser = {
        id: 'mock-user-123',
        email: email,
        user_metadata: { name: username || email.split('@')[0] },
        app_metadata: {},
        aud: 'authenticated',
        created_at: new Date().toISOString(),
      } as unknown as SupabaseUser

      setSuccessMsg('Signed in via Local Demo Mode (Supabase URL/Key not configured in .env.local).')
      setTimeout(() => {
        onAuthenticated(mockUser)
      }, 800)
      return
    }

    setLoading(true)

    try {
      if (isSignUp) {
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: {
              name: username,
              username: username,
            },
          },
        })

        if (error) throw error

        if (data.user) {
          if (data.session) {
            setSuccessMsg('Account created successfully!')
            setTimeout(() => onAuthenticated(data.user!), 600)
          } else {
            setSuccessMsg('Account created! Please check your email to confirm your registration.')
          }
        }
      } else {
        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        })

        if (error) throw error

        if (data.user) {
          setSuccessMsg('Logged in successfully!')
          setTimeout(() => onAuthenticated(data.user!), 500)
        }
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Authentication failed. Please check your credentials.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen w-full bg-[#f6f7fb] text-[#111827] flex flex-col justify-center items-center p-4 relative overflow-hidden font-sans">
      {/* Soft light background accents */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[500px] h-[500px] bg-[#5850ec]/10 rounded-full blur-[120px] pointer-events-none" />
      <div className="absolute bottom-10 right-1/4 w-[350px] h-[350px] bg-[#3b82f6]/10 rounded-full blur-[100px] pointer-events-none" />

      {/* Main Container Card */}
      <div className="w-full max-w-md bg-white border border-[#edeef3] rounded-2xl shadow-xl p-8 relative z-10">
        
        {/* Header Branding */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center p-2 bg-white border border-[#edeef3] rounded-2xl mb-3 shadow-md">
            <img
              src="/logo.jpg"
              alt="Cypher Lens Logo"
              className="h-14 w-auto object-contain rounded-xl"
            />
          </div>
          <h1 className="text-2xl font-extrabold text-[#111827] tracking-tight">
            Cypher Lens
          </h1>
          <p className="text-xs text-[#6b7280] font-medium mt-1">
            VPN Security Analyzer & Protocol Auditor
          </p>
        </div>

        {/* Supabase status warning notice if env not filled */}
        {!isSupabaseConfigured && (
          <div className="mb-6 p-3.5 bg-[#fffbeb] border border-[#fef3c7] rounded-xl text-[#b45309] text-xs flex items-start gap-2.5">
            <AlertCircle className="w-4 h-4 text-[#d97706] shrink-0 mt-0.5" />
            <div>
              <span className="font-bold block text-[#92400e]">Supabase Not Connected Yet</span>
              Add your <code className="bg-[#fef3c7] text-[#78350f] px-1 py-0.5 rounded font-mono">NEXT_PUBLIC_SUPABASE_URL</code> & key in <code className="bg-[#fef3c7] text-[#78350f] px-1 py-0.5 rounded font-mono">.env.local</code>. Logging in now will run in local demo mode.
            </div>
          </div>
        )}

        {/* Tab Selector */}
        <div className="flex bg-[#f3f4f6] p-1 rounded-xl border border-[#e5e7eb] mb-6">
          <button
            type="button"
            onClick={() => {
              setIsSignUp(false)
              setErrorMsg(null)
              setSuccessMsg(null)
            }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all duration-200 ${
              !isSignUp
                ? 'bg-[#5850ec] text-white shadow-md shadow-[#5850ec]/20'
                : 'text-[#6b7280] hover:text-[#111827]'
            }`}
          >
            Sign In
          </button>
          <button
            type="button"
            onClick={() => {
              setIsSignUp(true)
              setErrorMsg(null)
              setSuccessMsg(null)
            }}
            className={`flex-1 py-2 text-xs font-bold rounded-lg transition-all duration-200 ${
              isSignUp
                ? 'bg-[#5850ec] text-white shadow-md shadow-[#5850ec]/20'
                : 'text-[#6b7280] hover:text-[#111827]'
            }`}
          >
            Sign Up
          </button>
        </div>

        {/* Feedback Alerts */}
        {errorMsg && (
          <div className="mb-4 p-3 bg-[#fef2f2] border border-[#fecaca] rounded-xl text-[#b91c1c] text-xs flex items-center gap-2 font-medium">
            <AlertCircle className="w-4 h-4 text-[#ef4444] shrink-0" />
            <span>{errorMsg}</span>
          </div>
        )}

        {successMsg && (
          <div className="mb-4 p-3 bg-[#f0fdf4] border border-[#bbf7d0] rounded-xl text-[#15803d] text-xs flex items-center gap-2 font-medium">
            <CheckCircle2 className="w-4 h-4 text-[#10b981] shrink-0" />
            <span>{successMsg}</span>
          </div>
        )}

        {/* Auth Form */}
        <form onSubmit={handleAuth} className="space-y-4">
          {isSignUp && (
            <div>
              <label className="block text-xs font-bold text-[#374151] mb-1.5">
                Username / Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
                <input
                  type="text"
                  required={isSignUp}
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="john_doe"
                  className="w-full bg-white border border-[#d1d5db] rounded-xl pl-9 pr-3 py-2.5 text-xs text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#5850ec] focus:ring-1 focus:ring-[#5850ec] transition-colors font-medium"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-bold text-[#374151] mb-1.5">
              Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="user@organization.com"
                className="w-full bg-white border border-[#d1d5db] rounded-xl pl-9 pr-3 py-2.5 text-xs text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#5850ec] focus:ring-1 focus:ring-[#5850ec] transition-colors font-medium"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-bold text-[#374151] mb-1.5">
              Password
            </label>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#9ca3af]" />
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                minLength={6}
                className="w-full bg-white border border-[#d1d5db] rounded-xl pl-9 pr-3 py-2.5 text-xs text-[#111827] placeholder-[#9ca3af] focus:outline-none focus:border-[#5850ec] focus:ring-1 focus:ring-[#5850ec] transition-colors font-medium"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full mt-2 bg-[#5850ec] hover:bg-[#4f46e5] text-white font-bold py-2.5 px-4 rounded-xl text-xs flex items-center justify-center gap-2 transition-all duration-200 shadow-md shadow-[#5850ec]/25 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <span className="inline-block w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <>
                <span>{isSignUp ? 'Create Supabase Account' : 'Sign In to Cypher Lens'}</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </button>
        </form>

        {/* Footer info */}
        <div className="mt-6 pt-4 border-t border-[#edeef3] text-center text-[11px] text-[#9ca3af] flex items-center justify-between font-medium">
          <span className="flex items-center gap-1">
            <Lock className="w-3 h-3 text-[#9ca3af]" /> Supabase SSL Secured
          </span>
          <a
            href="https://supabase.com/dashboard"
            target="_blank"
            rel="noreferrer"
            className="hover:text-[#5850ec] transition-colors flex items-center gap-1 font-semibold"
          >
            Supabase Console <ExternalLink className="w-3 h-3" />
          </a>
        </div>

      </div>
    </div>
  )
}
