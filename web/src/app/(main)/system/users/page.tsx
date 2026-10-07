"use client";

import * as React from "react";

import { Button } from "@/components/ui/button";
import { type AuthUser, api } from "@/lib/api";

export default function UsersPage() {
  const [users, setUsers] = React.useState<AuthUser[]>([]);
  const [error, setError] = React.useState("");
  const load = React.useCallback(
    () =>
      api
        .authUsers()
        .then((r) => setUsers(r.users ?? []))
        .catch((e) => setError(e.message)),
    [],
  );
  React.useEffect(() => {
    load();
  }, [load]);
  async function update(u: AuthUser, status: AuthUser["status"]) {
    try {
      await api.updateAuthUser(u.id, status, u.role);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "변경하지 못했습니다");
    }
  }
  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">사용자 관리</h1>
        <p className="text-sm text-muted-foreground">Google 로그인 사용자를 승인하거나 사용 중지합니다.</p>
      </div>
      {error && <p className="text-sm text-destructive">{error}</p>}
      <div className="overflow-x-auto rounded-lg border">
        <table className="w-full text-sm">
          <thead className="bg-muted/50">
            <tr>
              <th className="p-3 text-left">사용자</th>
              <th className="p-3 text-left">역할</th>
              <th className="p-3 text-left">상태</th>
              <th className="p-3 text-right">관리</th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-t">
                <td className="p-3">
                  <div className="font-medium">{u.name || u.email}</div>
                  <div className="text-muted-foreground">{u.email}</div>
                </td>
                <td className="p-3">{u.role}</td>
                <td className="p-3">{u.status}</td>
                <td className="space-x-2 p-3 text-right">
                  {u.status !== "approved" && (
                    <Button size="sm" onClick={() => update(u, "approved")}>
                      승인
                    </Button>
                  )}
                  {u.status !== "disabled" && (
                    <Button size="sm" variant="destructive" onClick={() => update(u, "disabled")}>
                      중지
                    </Button>
                  )}
                  {u.status === "disabled" && (
                    <Button size="sm" variant="outline" onClick={() => update(u, "approved")}>
                      복구
                    </Button>
                  )}
                </td>
              </tr>
            ))}
            {!users.length && (
              <tr>
                <td colSpan={4} className="p-8 text-center text-muted-foreground">
                  등록된 Google 사용자가 없습니다.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
