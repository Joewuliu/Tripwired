import { Brand } from './Brand.tsx'

export function NotFound({ message = "There's nothing at this address." }: { message?: string }) {
  return (
    <main className="page">
      <Brand />
      <section className="glass">
        <h1>{message}</h1>
        <p>
          <a href="/">Back to the start</a>
        </p>
      </section>
    </main>
  )
}
