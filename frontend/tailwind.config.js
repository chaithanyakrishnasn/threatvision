/** @type {import('tailwindcss').Config} */
module.exports = {
  darkMode: 'class',
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Exact ThreatVision SOC palette
        bg:      '#0a0e1a',
        surface: '#0f1629',
        card:    '#141d35',
        border:  '#1e2d4a',
        // Accents
        cyan:    '#00d4ff',
        danger:  '#ff3b6b',
        warning: '#ffb800',
        success: '#00ff9d',
        // Text
        primary: '#e8eaf0',
        muted:   '#6b7a99',
        // Named surface shades (legacy compat)
        'surface-900': '#0a0e1a',
        'surface-800': '#0f1629',
        'surface-700': '#141d35',
        'surface-600': '#1a2540',
        'surface-500': '#1e2d4a',
        'surface-400': '#253560',
        // Threat severity
        threat: {
          critical: '#ff3b6b',
          high:     '#ff6b35',
          medium:   '#ffb800',
          low:      '#00ff9d',
        },
        brand: {
          400: '#00d4ff',
          500: '#0ea5e9',
        },
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      animation: {
        'pulse-threat': 'pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'slide-in':     'slideIn 0.3s ease-out',
        'fade-in':      'fadeIn 0.4s ease-out',
        'arc':          'arcMove 2s linear infinite',
        'ping-slow':    'ping 2s cubic-bezier(0, 0, 0.2, 1) infinite',
      },
      keyframes: {
        slideIn: {
          '0%':   { transform: 'translateX(-100%)', opacity: '0' },
          '100%': { transform: 'translateX(0)',      opacity: '1' },
        },
        fadeIn: {
          '0%':   { opacity: '0', transform: 'translateY(8px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        arcMove: {
          '0%':   { strokeDashoffset: '200' },
          '100%': { strokeDashoffset: '0' },
        },
      },
    },
  },
  plugins: [],
}
