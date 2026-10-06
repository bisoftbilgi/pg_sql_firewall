-- Runs after the generated administrative functions exist.
-- PUBLIC must not execute pause, resume, detailed status, or cache clearing.
-- The functions also reject a non-superuser session_user at runtime.
REVOKE ALL ON FUNCTION public.sql_firewall_pause_approval_worker() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_resume_approval_worker() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_approval_worker_status() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_clear_approval_cache() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_queue_statistics() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_library_version() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.sql_firewall_require_preload() FROM PUBLIC;
