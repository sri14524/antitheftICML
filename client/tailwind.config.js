/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        cyber: {
          950: '#070a13',
          900: '#0b1120',
          850: '#0f172a',
          800: '#131e36',
          700: '#1e293b',
          border: 'rgba(56, 189, 248, 0.15)',
          neonCyan: '#06b6d4',
          neonEmerald: '#10b981',
          neonAmber: '#f59e0b',
          neonRose: '#f43f5e',
          neonPurple: '#a855f7',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-glow': 'pulse-glow 2.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'radar-sweep': 'radar-sweep 4s linear infinite',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { opacity: '0.8', filter: 'drop-shadow(0 0 12px rgba(6, 182, 212, 0.4))' },
          '50%': { opacity: '0.4', filter: 'drop-shadow(0 0 4px rgba(6, 182, 212, 0.2))' },
        },
        'radar-sweep': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        }
      }
    },
  },
  plugins: [],
}
