import { Sidebar } from '@/components/Sidebar'
import { Footer } from '@/components/Footer'

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex min-h-dvh">
      <Sidebar />
      <main className="flex-1 lg:pl-64 transition-all duration-300 flex flex-col">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 pt-20 lg:pt-8 flex-1 w-full">
          {children}
        </div>
        <Footer />
      </main>
    </div>
  )
}
