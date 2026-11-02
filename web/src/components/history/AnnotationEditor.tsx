import { useState } from "react";
import type { ScanHistoryEntry, ScanAnnotationUpdate } from "../../types";

function parseTags(input: string): string[] {
  return input
    .split(",")
    .map((t) => t.trim().replace(/\s+/g, " "))
    .filter(Boolean);
}

export function AnnotationEditor({
  scan,
  onSave,
  onCancel,
}: {
  scan: ScanHistoryEntry;
  onSave: (update: ScanAnnotationUpdate) => Promise<void>;
  onCancel: () => void;
}) {
  const [tagText, setTagText] = useState(scan.tags.join(", "));
  const [notes, setNotes] = useState(scan.notes);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    setSaving(true);
    setError(null);
    try {
      await onSave({ tags: parseTags(tagText), notes });
    } catch (e) {
      setError(e instanceof Error ? e.message : "Save failed");
      setSaving(false);
    }
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-[1fr_2fr_auto] gap-3 items-start">
      <label className="block">
        <span className="text-[11px] text-gray-500 uppercase tracking-wide">Tags (comma-separated)</span>
        <input
          type="text"
          value={tagText}
          onChange={(e) => setTagText(e.target.value)}
          placeholder="pre-patch, lab"
          className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-xs text-white focus:border-emerald-500 focus:outline-none"
        />
      </label>
      <label className="block">
        <span className="text-[11px] text-gray-500 uppercase tracking-wide">Notes</span>
        <textarea
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          maxLength={2000}
          rows={2}
          placeholder="Context for this scan, e.g. firmware version or what changed"
          className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-2 py-1.5 text-xs text-white focus:border-emerald-500 focus:outline-none"
        />
      </label>
      <div className="flex md:flex-col gap-2 md:pt-5">
        <button
          onClick={handleSave}
          disabled={saving}
          className="px-3 py-1.5 text-xs font-medium rounded-md bg-emerald-600 hover:bg-emerald-500 text-white disabled:bg-gray-700"
        >
          {saving ? "Saving..." : "Save"}
        </button>
        <button
          onClick={onCancel}
          className="px-3 py-1.5 text-xs rounded-md text-gray-400 hover:text-white bg-gray-800 hover:bg-gray-700"
        >
          Cancel
        </button>
      </div>
      {error && <p className="md:col-span-3 text-xs text-red-400">{error}</p>}
    </div>
  );
}
