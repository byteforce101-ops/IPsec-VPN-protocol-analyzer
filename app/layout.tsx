import { Analytics } from '@vercel/analytics/next'
import type { Metadata, Viewport } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Cypher Lens — IPsec VPN Security Analyzer & Protocol Auditor',
  description: 'AI-powered IPsec VPN security auditing, traffic classification, and NIST SP 800-77 risk assessment platform.',
  generator: 'Antigravity Platform',
  icons: {
    icon: '/favicon.ico',
  },
}

export const viewport: Viewport = {
  colorScheme: 'light',
  themeColor: '#f6f7fb',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en">
      <body className="bg-[#f6f7fb] text-[#111827] antialiased selection:bg-[#5850ec]/20 selection:text-[#5850ec] overflow-hidden">
        {children}
        {process.env.NODE_ENV === 'production' && <Analytics />}
      </body>
    </html>
  )
}
