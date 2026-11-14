/**
 * `tenancyAudit`: inspect a live database for the tenancy mistakes ADR-0007 forbids. Run it from
 * `sv doctor`, in CI after migrations, or in a health check. An empty result means every
 * tenant-scoped table is protected and the runtime role cannot bypass RLS.
 *
 * Run it **as the runtime role** (the role the app connects as), so the role checks are about
 * the right role. Role checks follow membership: owning a table through a group role, or being
 * able to assume a superuser/BYPASSRLS role, counts like having it directly. A tenant policy only
 * counts when it is RESTRICTIVE, `FOR ALL`, applies to every role (no `TO …`) and both its USING
 * and WITH CHECK read the tenant setting. A role- or database-level default for the tenant setting
 * (`ALTER ROLE … SET app.tenant_id`) is flagged too.
 *
 * @module
 */

/** The minimal client shape (satisfied by `pg.Pool`, `pg.Client` and PGlite). */
export interface Queryable {
  query(text: string, values?: unknown[]): Promise<{ rows: unknown[] }>
}

/** One problem found by {@link tenancyAudit}. */
export interface TenancyFinding {
  readonly severity: 'error' | 'warning'
  readonly code:
    | 'RLS_DISABLED'
    | 'RLS_NOT_FORCED'
    | 'NO_RESTRICTIVE_POLICY'
    | 'RUNTIME_ROLE_BYPASSES_RLS'
    | 'RUNTIME_ROLE_OWNS_TABLE'
    | 'DEFINER_VIEW'
    | 'SECURITY_DEFINER_FUNCTION'
    | 'TENANT_SETTING_DEFAULT'
  /** `schema.name` of the object, when the finding is about one. */
  readonly object?: string
  readonly message: string
}

/** Options for {@link tenancyAudit}. */
export interface TenancyAuditOptions {
  /** The tenant column name. Default `tenant_id`. */
  readonly column?: string
  /** The setting the tenant policies read. Default `app.tenant_id`. */
  readonly setting?: string
}

const SYSTEM_SCHEMAS = `n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%'`

const TABLES = `
SELECT n.nspname || '.' || c.relname AS object,
       c.relrowsecurity AS enabled,
       c.relforcerowsecurity AS forced,
       pg_catalog.pg_has_role(current_user, c.relowner, 'MEMBER') AS owned,
       EXISTS (SELECT 1 FROM pg_catalog.pg_policy p
               WHERE p.polrelid = c.oid AND NOT p.polpermissive AND p.polcmd = '*'
                 AND p.polroles = '{0}'::oid[]
                 AND strpos(pg_catalog.pg_get_expr(p.polqual, p.polrelid), $2) > 0
                 AND strpos(pg_catalog.pg_get_expr(p.polqual, p.polrelid), $1) > 0
                 AND (p.polwithcheck IS NULL
                      OR (strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), $2) > 0
                          AND strpos(pg_catalog.pg_get_expr(p.polwithcheck, p.polrelid), $1) > 0))) AS restrictive
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attname = $1 AND NOT a.attisdropped
WHERE c.relkind IN ('r', 'p') AND ${SYSTEM_SCHEMAS}
ORDER BY 1`

const ROLE = `
SELECT current_user AS role, r.rolsuper AS super, r.rolbypassrls AS bypass
FROM pg_catalog.pg_roles r WHERE r.rolname = current_user`

const ASSUMABLE = `
SELECT r.rolname AS role, r.rolsuper AS super, r.rolbypassrls AS bypass
FROM pg_catalog.pg_roles r
WHERE (r.rolsuper OR r.rolbypassrls) AND r.rolname <> current_user
  AND pg_catalog.pg_has_role(current_user, r.oid, 'MEMBER')
ORDER BY 1`

const SETTING_DEFAULTS = `
SELECT coalesce(r.rolname, '(all roles)') AS role, coalesce(d.datname, '(all databases)') AS db
FROM pg_catalog.pg_db_role_setting s
LEFT JOIN pg_catalog.pg_roles r ON r.oid = s.setrole
LEFT JOIN pg_catalog.pg_database d ON d.oid = s.setdatabase
WHERE EXISTS (SELECT 1 FROM unnest(s.setconfig) c WHERE lower(split_part(c, '=', 1)) = $1)
ORDER BY 1, 2`

const VIEWS = `
SELECT DISTINCT n.nspname || '.' || v.relname AS object, v.relkind AS kind
FROM pg_catalog.pg_class v
JOIN pg_catalog.pg_namespace n ON n.oid = v.relnamespace
JOIN pg_catalog.pg_rewrite r ON r.ev_class = v.oid
JOIN pg_catalog.pg_depend d ON d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid = r.oid
                           AND d.refclassid = 'pg_catalog.pg_class'::regclass
JOIN pg_catalog.pg_class t ON t.oid = d.refobjid AND t.relkind IN ('r', 'p') AND t.oid <> v.oid
JOIN pg_catalog.pg_attribute a ON a.attrelid = t.oid AND a.attname = $1 AND NOT a.attisdropped
WHERE v.relkind IN ('v', 'm') AND ${SYSTEM_SCHEMAS}
  AND (v.relkind = 'm' OR NOT EXISTS (
        SELECT 1 FROM unnest(coalesce(v.reloptions, '{}'::text[])) o
        WHERE lower(o) IN ('security_invoker=true', 'security_invoker=on', 'security_invoker=1', 'security_invoker=yes')))
ORDER BY 1`

const FUNCTIONS = `
SELECT n.nspname || '.' || p.proname AS object
FROM pg_catalog.pg_proc p
JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
WHERE p.prosecdef AND ${SYSTEM_SCHEMAS}
  AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d
                  WHERE d.classid = 'pg_catalog.pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e')
ORDER BY 1`

const COLUMN = /^[a-z_][a-z0-9_]{0,62}$/
const SETTING = /^[a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*$/

/** Inspect the database. Returns findings, most severe first; empty means protected. */
export async function tenancyAudit(
  db: Queryable,
  options: TenancyAuditOptions = {},
): Promise<TenancyFinding[]> {
  const column = options.column ?? 'tenant_id'
  if (!COLUMN.test(column)) throw new TypeError(`Invalid column name ${JSON.stringify(column)}`)
  const setting = options.setting ?? 'app.tenant_id'
  if (!SETTING.test(setting)) throw new TypeError(`Invalid setting name ${JSON.stringify(setting)}`)
  const findings: TenancyFinding[] = []

  const role = (await db.query(ROLE)).rows[0] as
    | { role: string; super: boolean; bypass: boolean }
    | undefined
  if (role && (role.super || role.bypass)) {
    findings.push({
      severity: 'error',
      code: 'RUNTIME_ROLE_BYPASSES_RLS',
      object: role.role,
      message: `Role "${role.role}" is ${role.super ? 'a superuser' : 'BYPASSRLS'}: row-level security never applies to it. Connect the app as a dedicated runtime role.`,
    })
  } else if (role) {
    // Attributes are not inherited, but a member can SET ROLE to the privileged role.
    const assumable = (await db.query(ASSUMABLE)).rows as {
      role: string
      super: boolean
      bypass: boolean
    }[]
    for (const r of assumable) {
      findings.push({
        severity: 'error',
        code: 'RUNTIME_ROLE_BYPASSES_RLS',
        object: role.role,
        message: `Role "${role.role}" is a member of "${r.role}", which is ${r.super ? 'a superuser' : 'BYPASSRLS'}; it can SET ROLE and bypass row-level security. Revoke the membership.`,
      })
    }
  }

  for (const d of (await db.query(SETTING_DEFAULTS, [setting])).rows as {
    role: string
    db: string
  }[]) {
    findings.push({
      severity: 'error',
      code: 'TENANT_SETTING_DEFAULT',
      object: d.role,
      message: `A default for ${setting} is configured (role ${d.role}, database ${d.db}): every new session would start inside a tenant. Remove it (ALTER ROLE … RESET ${setting}); set the tenant per transaction only.`,
    })
  }

  const tables = (await db.query(TABLES, [column, `current_setting('${setting}'`])).rows as {
    object: string
    enabled: boolean
    forced: boolean
    owned: boolean
    restrictive: boolean
  }[]
  for (const t of tables) {
    if (!t.enabled) {
      findings.push({
        severity: 'error',
        code: 'RLS_DISABLED',
        object: t.object,
        message: `Row-level security is not enabled on ${t.object}.`,
      })
    } else if (!t.forced) {
      findings.push({
        severity: 'error',
        code: 'RLS_NOT_FORCED',
        object: t.object,
        message: `Row-level security is not FORCED on ${t.object}, so it does not apply to the table owner.`,
      })
    }
    if (!t.restrictive) {
      findings.push({
        severity: 'error',
        code: 'NO_RESTRICTIVE_POLICY',
        object: t.object,
        message: `${t.object} has no RESTRICTIVE FOR ALL tenant policy that applies to every role and checks ${column} against current_setting('${setting}') in both USING and WITH CHECK; a permissive policy can expose every tenant.`,
      })
    }
    if (t.owned) {
      findings.push({
        severity: 'error',
        code: 'RUNTIME_ROLE_OWNS_TABLE',
        object: t.object,
        message: `The current role owns ${t.object} (directly or through role membership); owners can disable FORCE ROW LEVEL SECURITY. Use a separate owner role for migrations.`,
      })
    }
  }

  for (const v of (await db.query(VIEWS, [column])).rows as { object: string; kind: string }[]) {
    findings.push({
      severity: 'error',
      code: 'DEFINER_VIEW',
      object: v.object,
      message:
        v.kind === 'm'
          ? `Materialized view ${v.object} stores tenant rows outside row-level security.`
          : `View ${v.object} reads a tenant table without security_invoker, so RLS is checked as the view owner.`,
    })
  }

  for (const f of (await db.query(FUNCTIONS)).rows as { object: string }[]) {
    findings.push({
      severity: 'warning',
      code: 'SECURITY_DEFINER_FUNCTION',
      object: f.object,
      message: `Function ${f.object} is SECURITY DEFINER; it must not read tenant tables (it would run with its owner's rights).`,
    })
  }

  return findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === 'error' ? -1 : 1))
}
