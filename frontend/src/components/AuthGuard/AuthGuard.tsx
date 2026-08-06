import { Outlet } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";
import { DelayedLoader } from "@/components/DelayedLoader/DelayedLoader";

// Gates protected routes. Local /login is gone — identity comes from the
// gateway. A 401 here means the gateway headers never reached the app.
export function AuthGuard() {
  const { data, isLoading, error } = useMe();

  if (isLoading) {
    return <DelayedLoader />;
  }

  if (error) {
    if (error instanceof ApiError && error.isAuthError()) {
      return (
        <main style={{ padding: "2rem", fontFamily: "system-ui" }}>
          <h1>Sign-in required</h1>
          <p>Open this app through the gateway so authentik can authenticate you.</p>
        </main>
      );
    }
    throw error;
  }

  if (!data) {
    return (
      <main style={{ padding: "2rem", fontFamily: "system-ui" }}>
        <h1>Sign-in required</h1>
        <p>Open this app through the gateway so authentik can authenticate you.</p>
      </main>
    );
  }

  return <Outlet />;
}
