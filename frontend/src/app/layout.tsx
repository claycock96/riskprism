import type { Metadata } from 'next'
import './globals.css'

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
            <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
              <h1 className="text-2xl font-bold text-gray-900">
                Terraform Plan Analyzer
              </h1>
              <p className="text-sm text-gray-600 mt-1">
                Security-focused analysis with AI-powered explanations
              </p>
            </div>
          </header>
          <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            {children}
          </main>
        </div>
      </body>
    </html>
  )
}
