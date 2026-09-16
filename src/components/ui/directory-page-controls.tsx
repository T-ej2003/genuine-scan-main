export function DirectoryPageControls({ offset, total, loading, onChange }: {
  offset: number; total?: number; loading: boolean; onChange: (offset: number) => void;
}) {
  return <nav aria-label="User directory pages" className="flex items-center gap-3 text-sm">
    <button type="button" disabled={loading || offset === 0} onClick={() => onChange(Math.max(0, offset - 100))}>Previous users</button>
    <span>User page {offset / 100 + 1}{total !== undefined ? ` of ${Math.max(1, Math.ceil(total / 100))}` : ""}</span>
    <button type="button" disabled={loading || total === undefined || offset + 100 >= total} onClick={() => onChange(offset + 100)}>Next users</button>
  </nav>;
}
