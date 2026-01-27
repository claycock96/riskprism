import type { Metadata } from 'next'
import Link from 'next/link'
import './globals.css'
import SystemStats from '@/components/SystemStats'
import Gatekeeper from '@/components/Gatekeeper'

export const metadata: Metadata = {
  title: 'RiskPrism',
  description: 'Turn change into clear decisions with AI-powered risk and explanations.',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen">
        {/* Ambient background glow effects */}
        <div className="fixed inset-0 overflow-hidden pointer-events-none">
          <div className="absolute top-0 left-1/4 w-96 h-96 bg-violet-600/10 rounded-full blur-3xl" />
          <div className="absolute top-1/3 right-1/4 w-80 h-80 bg-fuchsia-600/10 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 left-1/3 w-72 h-72 bg-cyan-600/10 rounded-full blur-3xl" />
        </div>

        <div className="relative min-h-screen">
          {/* Glassmorphic Header */}
          <header className="sticky top-0 z-50 border-b border-white/10 bg-slate-950/80 backdrop-blur-xl">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
              <div className="flex items-center gap-4">
                {/* Logo with animated glow */}
                <Link href="/" className="group flex items-center gap-3">
                  <div className="relative">
                    <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-fuchsia-500 flex items-center justify-center shadow-glow-md group-hover:shadow-glow-lg transition-shadow duration-300">
                      <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                      </svg>
                    </div>
                    {/* Pulsing glow ring */}
                    <div className="absolute inset-0 w-10 h-10 rounded-xl bg-violet-500/30 animate-pulse-slow opacity-0 group-hover:opacity-100 transition-opacity" />
                  </div>
                  <div>
                    <h1 className="text-xl font-bold bg-gradient-to-r from-white via-violet-200 to-fuchsia-200 bg-clip-text text-transparent">
                      RiskPrism
                    </h1>
                    <p className="text-xs text-slate-400 hidden sm:block">
                      AI-powered infrastructure risk analysis
                    </p>
                  </div>
                </Link>
              </div>

              {/* Right side navigation/actions */}
              <div className="flex items-center gap-4">
              </div>
            </div>
          </header>

          {/* Main content */}
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Gatekeeper>
              {children}
              <SystemStats />
            </Gatekeeper>
          </main>

          {/* Footer gradient fade */}
          <div className="fixed bottom-0 inset-x-0 h-32 bg-gradient-to-t from-slate-950 to-transparent pointer-events-none" />
        </div>
      </body>
    </html>
  )
}
