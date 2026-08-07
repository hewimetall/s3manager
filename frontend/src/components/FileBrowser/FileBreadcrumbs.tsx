import { Anchor, Breadcrumbs, Text } from "@mantine/core";
import { Link } from "react-router-dom";
import { Home } from "lucide-react";
import { splitCrumbs, roleEntryPath, clampPathToEntry, encodePath } from "@/utils/pathUtils";
import { useConfig } from "@/hooks/useConfig";
import classes from "./FileBrowser.module.css";

interface FileBreadcrumbsProps {
  bucket: string;
  roleId: string;
  path: string;
}

export function FileBreadcrumbs({ bucket, roleId, path }: FileBreadcrumbsProps) {
  const { data: config } = useConfig();
  const role = config?.roles?.find((r) => r.name === roleId);
  const entryPath = roleEntryPath(role?.allowed_prefixes);
  const crumbs = splitCrumbs(path).filter((c) => {
    // Hide crumb segments above the role's single allowed prefix so "Up" /
    // intermediate links cannot climb into the shared-bucket root.
    if (!entryPath) return true;
    return c.path === entryPath || c.path.startsWith(entryPath + "/");
  });
  const baseUrl = `/r/${encodeURIComponent(roleId)}/b/${encodeURIComponent(bucket)}`;
  const homePath = clampPathToEntry("", entryPath);
  const homeUrl = homePath
    ? `${baseUrl}/p/${encodePath(homePath)}`
    : baseUrl;

  return (
    // wrap: on phones a deep path folds to a second line instead of
    // overflowing the pinned toolbar row.
    <Breadcrumbs style={{ flexWrap: "wrap", rowGap: 4 }}>
      <Anchor
        component={Link}
        to={homeUrl}
        size="sm"
        className={classes.crumb}
        title={entryPath || bucket}
      >
        <Home size={14} style={{ verticalAlign: "middle", marginRight: 4 }} />
        {entryPath || bucket}
      </Anchor>
      {crumbs
        .filter((c) => !(entryPath && c.path === entryPath))
        .map((c, i, visible) => {
        const isLast = i === visible.length - 1;
        const url = `${baseUrl}/p/${c.path.split("/").map(encodeURIComponent).join("/")}`;
        return isLast ? (
          <Text
            key={c.path}
            size="sm"
            fw={500}
            className={classes.crumb}
            title={c.name}
          >
            {c.name}
          </Text>
        ) : (
          <Anchor
            component={Link}
            to={url}
            key={c.path}
            size="sm"
            className={classes.crumb}
            title={c.name}
          >
            {c.name}
          </Anchor>
        );
      })}
    </Breadcrumbs>
  );
}
