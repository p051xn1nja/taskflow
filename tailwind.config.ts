import type { Config } from 'tailwindcss'

const config: Config = {
  content: [
    './src/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eef8ff',
          100: '#d8eeff',
          200: '#b9e0ff',
          300: '#89cfff',
          400: '#52b4ff',
          500: '#2a91ff',
          600: '#1a75f5',
          700: '#1260e1',
          800: '#164db6',
          900: '#18438f',
          950: '#142a57',
        },
        surface: {
          0: '#131828',
          50: '#181e32',
          100: '#1e2640',
          200: '#252e4e',
          300: '#2d385e',
          400: '#374470',
          500: '#455584',
          600: '#596b9a',
          700: '#7b8db8',
          800: '#a0aed0',
          900: '#cdd5e5',
          950: '#eef0f6',
        },
        accent: {
          green: '#22c55e',
          cyan: '#22d3ee',
          amber: '#f59e0b',
          red: '#ef4444',
          purple: '#a855f7',
        },
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
      },
      animation: {
        'fade-in': 'fadeIn 0.2s ease-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'slide-down': 'slideDown 0.2s ease-out',
        'scale-in': 'scaleIn 0.15s ease-out',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { opacity: '0', transform: 'translateY(10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        slideDown: {
          '0%': { opacity: '0', transform: 'translateY(-10px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        scaleIn: {
          '0%': { opacity: '0', transform: 'scale(0.95)' },
          '100%': { opacity: '1', transform: 'scale(1)' },
        },
      },
    },
  },
  plugins: [],
}
export default config
