import { useState } from "react";
import { FolderTree, File, AlertTriangle, ChevronRight, ChevronDown, Loader2 } from "lucide-react";
import { api } from "../api/client";
import type { FilesystemResult } from "../types";

export function Explorer() {
  const [host, setHost] = useState("192.168.1.1");
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FilesystemResult | null>(null);

  const handleExplore = async () => {
    if (!host || !password) return;
    setLoading(true);
    setError(null);
    try {
      const res = await api.filesystem(host, username, password);
      setResult(res);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Exploration failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-6 max-w-5xl">
      <div>
        <h1 className="text-xl font-semibold text-white">Filesystem Explorer</h1>
        <p className="text-sm text-gray-500">Explore remote device file system over SSH</p>
      </div>

      {/* Connection form */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
        <div className="flex items-end gap-3">
          <div className="flex-1">
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">Host</label>
            <input
              type="text"
              value={host}
              onChange={(e) => setHost(e.target.value)}
              className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div className="w-32">
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">Username</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <div className="w-40">
            <label className="text-[11px] text-gray-500 uppercase tracking-wide">Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="mt-1 w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm text-white focus:border-emerald-500 focus:outline-none"
            />
          </div>
          <button
            onClick={handleExplore}
            disabled={loading || !host || !password}
            className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 disabled:bg-gray-700 disabled:text-gray-500 text-white text-sm font-medium rounded-md transition-colors whitespace-nowrap"
          >
            {loading ? "Exploring..." : "Explore"}
          </button>
        </div>
      </div>

      {loading && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6 flex items-center gap-3">
          <Loader2 className="w-5 h-5 text-emerald-400 animate-spin" />
          <div>
            <p className="text-sm text-white">Exploring filesystem...</p>
            <p className="text-xs text-gray-500">Connecting via SSH and scanning directories. This may take a few seconds.</p>
          </div>
        </div>
      )}

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-md p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {!loading && result && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* File tree */}
          <div className="lg:col-span-2 bg-gray-900 border border-gray-800 rounded-lg p-4 max-h-[600px] overflow-y-auto">
            <h2 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
              <FolderTree className="w-4 h-4 text-emerald-400" />
              File Structure
            </h2>
            <div className="space-y-1">
              {Object.entries(result.file_structure).map(([path, files]) => (
                <DirectoryNode key={path} path={path} files={files as FileEntry[]} />
              ))}
            </div>
          </div>

          {/* Findings sidebar */}
          <div className="space-y-4">
            {result.interesting_files.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                <h2 className="text-sm font-medium text-gray-300 mb-3">Interesting Files</h2>
                <div className="space-y-2">
                  {result.interesting_files.map((f, i) => (
                    <div key={i} className="flex items-start gap-2 text-xs">
                      <File className="w-3 h-3 text-amber-400 mt-0.5 flex-shrink-0" />
                      <div>
                        <p className="text-gray-300 font-mono">{f.path}</p>
                        <p className="text-gray-500">{f.reason}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.security_findings.length > 0 && (
              <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
                <h2 className="text-sm font-medium text-gray-300 mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  Security Findings
                </h2>
                <div className="space-y-2">
                  {result.security_findings.map((f, i) => (
                    <div
                      key={i}
                      className={`text-xs p-2 rounded border ${
                        f.severity === "high"
                          ? "border-red-500/30 bg-red-500/5 text-red-300"
                          : f.severity === "medium"
                            ? "border-amber-500/30 bg-amber-500/5 text-amber-300"
                            : "border-gray-700 text-gray-400"
                      }`}
                    >
                      <p>{f.description}</p>
                      {f.file && <p className="font-mono text-[10px] mt-1 opacity-70">{f.file}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

interface FileEntry {
  name: string;
  permissions: string;
}

function DirectoryNode({ path, files }: { path: string; files: FileEntry[] }) {
  const [open, setOpen] = useState(false);

  return (
    <div>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 text-xs text-gray-300 hover:text-white py-0.5 w-full text-left"
      >
        {open ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
        <FolderTree className="w-3 h-3 text-emerald-400" />
        <span className="font-mono">{path}/</span>
        <span className="text-gray-600 ml-1">({files.length})</span>
      </button>
      {open && (
        <div className="ml-5 border-l border-gray-800 pl-2 space-y-0.5">
          {files.slice(0, 20).map((f, i) => (
            <div key={i} className="flex items-center gap-2 text-[11px] text-gray-500 py-0.5">
              <File className="w-3 h-3" />
              <span className="font-mono text-gray-600 w-24">{f.permissions}</span>
              <span className="text-gray-400">{f.name}</span>
            </div>
          ))}
          {files.length > 20 && (
            <p className="text-[10px] text-gray-600 pl-5">...and {files.length - 20} more</p>
          )}
        </div>
      )}
    </div>
  );
}
