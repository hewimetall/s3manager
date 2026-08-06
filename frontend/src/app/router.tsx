import { createBrowserRouter, Navigate } from "react-router-dom";
import { AdminGuard } from "@/components/AdminLayout/AdminGuard";
import { AdminLayout } from "@/components/AdminLayout/AdminLayout";
import { AppShellLayout } from "@/components/AppShell/AppShellLayout";
import { AuthGuard } from "@/components/AuthGuard/AuthGuard";
import { ErrorPage } from "@/pages/ErrorPage";
import { HomePage } from "@/pages/HomePage";
import { NotFoundPage } from "@/pages/NotFoundPage";
import { RolePage } from "@/pages/RolePage";
import { BucketPage } from "@/pages/BucketPage";
import { RolesPage } from "@/pages/admin/RolesPage";
import { SettingsPage } from "@/pages/admin/SettingsPage";

export const router = createBrowserRouter(
  [
    {
      element: <AuthGuard />,
      errorElement: <ErrorPage />,
      children: [
        {
          element: <AppShellLayout />,
          children: [
            { path: "/", element: <HomePage /> },
            { path: "/r/:roleId", element: <RolePage /> },
            { path: "/r/:roleId/b/:bucket", element: <BucketPage /> },
            { path: "/r/:roleId/b/:bucket/p/*", element: <BucketPage /> },
          ],
        },
        {
          element: <AdminGuard />,
          children: [
            {
              element: <AdminLayout />,
              children: [
                {
                  path: "/admin",
                  element: <Navigate to="/admin/roles" replace />,
                },
                { path: "/admin/roles", element: <RolesPage /> },
                { path: "/admin/roles/new", element: <RolesPage /> },
                { path: "/admin/roles/:roleName", element: <RolesPage /> },
                { path: "/admin/settings", element: <SettingsPage /> },
              ],
            },
          ],
        },
      ],
    },
    {
      path: "*",
      element: <NotFoundPage />,
    },
  ],
);
