import type { Metadata } from 'next'
import Link from 'next/link'
import './globals.css'
import SystemStats from '@/components/SystemStats'

export const metadata: Metadata = {
  title: 'Terraform Plan Analyzer',
  description: 'Security-focused Terraform plan analysis with AI-powered explanations',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen">
          <header className="bg-white border-b border-gray-200 shadow-sm">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
              <div>
                <Link href="/">
                  <h1 className="text-2xl font-bold text-gray-900 hover:text-blue-600 transition-colors inline-block cursor-pointer">
                    Terraform Plan Analyzer
                  </h1>
                </Link>
                <p className="text-sm text-gray-600 mt-1">
                  Security-focused analysis with AI-powered explanations
                </p>
              </div>
              <nav>
                <Link
                  href="/history"
                  className="text-sm font-medium text-gray-500 hover:text-blue-600 transition-colors flex items-center"
                >
                  <span className="mr-1.5">🕒</span> History
                </Link>
              </nav>
            </div>
          </header>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {children}
            <SystemStats />
          </main>
        </div>
      </body>
    </html>
  )
}
