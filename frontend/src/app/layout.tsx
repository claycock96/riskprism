import type { Metadata } from 'next'
import Link from 'next/link'
import './globals.css'
import SystemStats from '@/components/SystemStats'
import Gatekeeper from '@/components/Gatekeeper'

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
      <body className="bg-gray-50 dark:bg-gray-900">
        <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
          <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 shadow-sm">
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex items-center justify-between">
              <div>
                <Link href="/">
                  <h1 className="text-2xl font-bold text-gray-900 dark:text-white hover:text-blue-600 dark:hover:text-blue-400 transition-colors inline-block cursor-pointer">
                    Terraform Plan Analyzer
                  </h1>
                </Link>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Security-focused analysis with AI-powered explanations
                </p>
              </div>
            </div>
          </header>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <Gatekeeper>
              {children}
              <SystemStats />
            </Gatekeeper>
          </main>
        </div>
      </body>
    </html>
  )
}
