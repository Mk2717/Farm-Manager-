export default function Home() {
  return (
    <main className="farm-manager-shell">
      <iframe
        className="farm-manager-frame"
        src="/index.html"
        title="Farm Manager application"
        allow="clipboard-write"
      />
    </main>
  );
}
