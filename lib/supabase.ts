import { createClient } from '@supabase/supabase-js'

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL || ''
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY || ''

// Check if credentials are properly provided
export const isSupabaseConfigured = Boolean(
  supabaseUrl &&
  supabaseAnonKey &&
  supabaseUrl !== 'https://your-supabase-project.supabase.co' &&
  !supabaseUrl.includes('your-supabase-project')
)

// Fallback dummy URL to prevent createClient runtime crash if env vars are missing during initial setup
const validUrl = isSupabaseConfigured ? supabaseUrl : 'https://placeholder.supabase.co'
const validKey = isSupabaseConfigured ? supabaseAnonKey : 'placeholder-key'

export const supabase = createClient(validUrl, validKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
})
