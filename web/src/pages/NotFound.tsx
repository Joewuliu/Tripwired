export function NotFound({ message = "There's nothing at this address." }: { message?: string }) {
  return (
    <main className="page">
      <p className="eyebrow">Tripwire</p>
      <h1>{message}</h1>
      <p>
        <a href="/">Back to the start</a>
      </p>
    </main>
  )
}
