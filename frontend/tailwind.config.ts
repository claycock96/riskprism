import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        critical: '#dc2626',
        high: '#f97316',
        medium: '#eab308',
        low: '#3b82f6',
        info: '#6b7280',
      },
    },
  },
  plugins: [],
}
export default config
