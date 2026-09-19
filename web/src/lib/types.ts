// Mirrors the control plane's JSON views (docs/API.md).
export type Role = 'endpoint' | 'subnet-router' | 'hub' | 'exit-node';
export interface Prefix { prefix: string; mode: 'routed' | 'snat' }
export interface Node {
  id: string; name: string; hostname?: string; platform?: string; key_kind?: string; hardware_bound: boolean; hardware_claimed?: boolean;
  spki: string; fingerprint: string; status: 'pending' | 'confirmed' | 'approved' | 'revoked';
  kind: 'interactive' | 'workload'; requested_roles: Role[]; requested_prefixes: Prefix[]; roles: Role[]; prefixes: Prefix[];
  overlay_ip?: string; public_addr?: string; key_version: number; signed: boolean; signed_by?: string; signed_at?: string;
  requested_at: string; request_ip?: string; confirmed_at?: string; confirmed_by?: string; approved_at?: string; approved_by?: string;
  revoked_at?: string; revoked_by?: string; last_seen_at?: string; snapshot_version: number; active_tunnels: number;
  sign_token?: string; sign_expires_at?: string; sign_command?: string;
}
export interface Grant { fingerprint?: string; name?: string; kind?: string; roles?: Role[]; prefixes?: Prefix[]; overlay_ip?: string; public_addr?: string; hardware_bound?: boolean }
export interface Signer { id: string; name: string; subject?: string; public_key: string; key_type: string; hardware: boolean; fingerprint: string; created_at: string; revoked_at?: string; active: boolean }
export interface SignerChange { version: number; keys: Signer[]; added: string[]; removed: string[]; affected_nodes: { id: string; name: string }[]; signable_by: string[]; sign_token: string; sign_command: string; sign_expires_at: string }
export interface SignerSet { version: number; hash?: string; genesis_hash?: string; history: { version: number; hash: string; signed_by: string; admin: string; created_at: string; added: string[]; removed: string[] }[] }
export interface Session { id: string; node_id: string; node_name?: string; subject: string; email?: string; username?: string; groups: string[]; login_ip?: string; issued_at: string; expires_at: string; ended_at?: string; ended_by?: string; end_reason?: string }
export interface Policy { id: string; name: string; description?: string; cedar: string; enabled: boolean; scope: string[]; created_at: string; created_by?: string; updated_at: string; updated_by?: string }
export interface PolicyBody { name: string; description: string; cedar: string; enabled: boolean; scope: string[] }
export interface EvaluateBody { node: string; dst: string; port?: number; proto?: string; sni?: string; dns_name?: string; enforcer?: string; draft?: { id: string; name: string; cedar: string }; draft_only?: boolean }
export interface Evaluation { allow: boolean; policies: string[]; reasons: string[]; errors?: string[]; policy_count: number; policy_errors?: string[]; principal: string; user?: string; groups?: string[]; owner?: string; owner_name?: string }
export interface Tunnel { id: string; hub_id: string; hub_name?: string; peer_id: string; peer_name?: string; peer_addr?: string; transport?: string; opened_at: string; closed_at?: string; close_reason?: string; bytes_in: number; bytes_out: number; packets_in: number; packets_out: number; last_report_at: string }
export interface LogEvent { id: number; ts: string; stream: string; actor?: string; device_id?: string; session_id?: string; message: string; attrs?: Record<string, unknown> }
export interface NetworkSettings { pool: string; max_age_seconds?: number }
export interface Passkey { id: string; subject: string; email?: string; label?: string; status: 'pending' | 'active' | 'revoked'; created_at: string; approved_at?: string; approved_by?: string; last_used_at?: string; revoked_at?: string; revoked_by?: string }
export interface ApiToken { id: string; name: string; created_by?: string; created_at: string; expires_at?: string; last_used_at?: string; revoked_at?: string; revoked_by?: string; token?: string }
export interface AuthStatus { level: 'none' | 'oidc_only' | 'full'; subject?: string; email?: string; name?: string; via?: string; own_passkeys: number; own_pending: number; total_passkeys: number; bootstrap_active: boolean; oidc_configured: boolean; passkeys_enabled: boolean; rp_id?: string; error?: string }
export interface Overview { nodes: Record<string, number>; active_sessions: number; active_tunnels: number; policies: number; policies_enabled: number; denied_last_24h: number; pending_passkeys: number; signers: number; snapshot_version: number }
