"use client";

import * as React from "react";

import { RefreshCw } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

type EgressRow = {
  ts?: number;
  event?: string;
  id?: string;
  method?: string;
  url?: string;
  host?: string;
  status?: number;
  sse?: boolean;
  error?: string;
  body?: { text?: string; base64?: string; truncated?: boolean; data?: unknown } | null;
};

function bodyPreview(body: EgressRow["body"]): string {
  if (!body) return "-";
  if (body.text) return body.text.slice(0, 1000);
  if (body.base64) return "[바이너리/base64]";
  if (body.data !== undefined) {
    return (typeof body.data === "string" ? body.data : JSON.stringify(body.data, null, 2)).slice(0, 1000);
  }
  return JSON.stringify(body, null, 2).slice(0, 1000);
}

export default function EgressLogsPage() {
  const [items, setItems] = React.useState<EgressRow[]>([]);
  const [q, setQ] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [available, setAvailable] = React.useState(true);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(`/api/egress-logs?limit=500${q.trim() ? `&q=${encodeURIComponent(q.trim())}` : ""}`);
      if (!res.ok) return;
      const data = (await res.json()) as { items?: EgressRow[]; available?: boolean };
      setItems(data.items ?? []);
      setAvailable(data.available !== false);
    } finally {
      setLoading(false);
    }
  }, [q]);

  React.useEffect(() => {
    void load();
    const timer = setInterval(() => void load(), 15000);
    return () => clearInterval(timer);
  }, [load]);

  return (
    <div className="flex flex-1 flex-col gap-4">
      <div>
        <h1 className="font-semibold text-xl tracking-tight">아웃바운드 요청 로그</h1>
        <p className="text-muted-foreground text-sm">
          MITM 사이드카가 기록한 네트워크 이벤트입니다. 인증·쿠키 헤더와 민감한 쿼리 값은 저장 전에 마스킹됩니다.
        </p>
      </div>
      <div className="flex gap-2">
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="호스트, URL, 이벤트 검색"
          className="max-w-md"
        />
        <Button variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCw className={loading ? "animate-spin" : ""} /> 새로고침
        </Button>
      </div>
      {!available && (
        <Card className="p-4 text-muted-foreground text-sm">프록시 로그 디렉터리가 아직 생성되지 않았습니다.</Card>
      )}
      <Card className="overflow-auto">
        <table className="w-full text-sm">
          <thead className="border-b text-left">
            <tr>
              <th className="p-3">시각</th>
              <th>이벤트</th>
              <th>요청</th>
              <th>상태</th>
              <th>본문 미리보기</th>
            </tr>
          </thead>
          <tbody>
            {[...items].reverse().map((row) => (
              <tr
                key={`${row.id ?? "event"}-${row.ts ?? "unknown"}-${row.event ?? "event"}`}
                className="border-b align-top last:border-0"
              >
                <td className="whitespace-nowrap p-3 text-muted-foreground">
                  {row.ts ? new Date(row.ts * 1000).toLocaleString("ko-KR") : "-"}
                </td>
                <td className="py-3">
                  <Badge variant="outline">{row.event ?? "-"}</Badge>
                  {row.sse && <Badge className="ml-1">SSE</Badge>}
                </td>
                <td className="max-w-xl py-3">
                  <div className="font-mono">
                    {row.method} {row.host}
                  </div>
                  <div className="break-all text-muted-foreground">{row.url}</div>
                </td>
                <td className="py-3">{row.status ?? row.error ?? "-"}</td>
                <td className="max-w-md whitespace-pre-wrap break-all py-3 font-mono text-xs">
                  {bodyPreview(row.body)}
                  {row.body?.truncated ? " …" : ""}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </div>
  );
}
