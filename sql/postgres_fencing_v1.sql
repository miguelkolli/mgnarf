-- MGnarf PostgreSQL fenced-target reference schema/functions v1.
-- Run as a dedicated schema/function owner. Runtime roles should receive only
-- EXECUTE on the functions they need; direct DML on fencing/effect tables is
-- not required by the reference adapters.

-- NARF_STATEMENT
CREATE TABLE IF NOT EXISTS public.narf_fence_scopes (
    scope_id text PRIMARY KEY,
    authority_revision bigint NOT NULL CHECK (authority_revision >= 0),
    fence_sequence bigint NOT NULL CHECK (fence_sequence >= 0)
);

-- NARF_STATEMENT
CREATE TABLE IF NOT EXISTS public.narf_fence_issuance (
    scope_id text NOT NULL REFERENCES public.narf_fence_scopes(scope_id),
    fence_sequence bigint NOT NULL CHECK (fence_sequence > 0),
    operation_id uuid NOT NULL UNIQUE,
    authority_revision bigint NOT NULL CHECK (authority_revision >= 0),
    effect_id text NOT NULL,
    effect_version text NOT NULL,
    authority_id text NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (scope_id, fence_sequence)
);

-- NARF_STATEMENT
CREATE TABLE IF NOT EXISTS public.narf_fenced_effects (
    operation_id uuid PRIMARY KEY,
    scope_id text NOT NULL,
    fence_sequence bigint NOT NULL,
    authority_revision bigint NOT NULL,
    effect_id text NOT NULL,
    effect_version text NOT NULL,
    payload text NOT NULL,
    committed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- NARF_STATEMENT
CREATE OR REPLACE FUNCTION public.narf_current_fence_revision(p_scope text)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_revision bigint;
BEGIN
    SELECT authority_revision INTO v_revision
    FROM public.narf_fence_scopes
    WHERE scope_id = p_scope;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'narf: unknown scope' USING ERRCODE = 'P0001';
    END IF;
    RETURN v_revision;
END;
$$;

-- NARF_STATEMENT
CREATE OR REPLACE FUNCTION public.narf_acquire_fence(
    p_scope text,
    p_operation uuid,
    p_expected_revision bigint,
    p_effect_id text,
    p_effect_version text,
    p_authority_id text
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_revision bigint;
    v_sequence bigint;
    v_next bigint;
BEGIN
    IF p_scope IS NULL OR p_operation IS NULL OR p_expected_revision IS NULL
       OR p_effect_id IS NULL OR p_effect_version IS NULL OR p_authority_id IS NULL THEN
        RAISE EXCEPTION 'narf: invalid fence request' USING ERRCODE = 'P0001';
    END IF;
    IF p_expected_revision < 0 THEN
        RAISE EXCEPTION 'narf: invalid fence request' USING ERRCODE = 'P0001';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_scope, 0));

    SELECT authority_revision, fence_sequence
    INTO v_revision, v_sequence
    FROM public.narf_fence_scopes
    WHERE scope_id = p_scope
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'narf: unknown scope' USING ERRCODE = 'P0001';
    END IF;
    IF v_revision <> p_expected_revision THEN
        RAISE EXCEPTION 'narf: authority revision changed' USING ERRCODE = 'P0001';
    END IF;

    v_next := v_sequence + 1;
    UPDATE public.narf_fence_scopes
    SET fence_sequence = v_next
    WHERE scope_id = p_scope;

    INSERT INTO public.narf_fence_issuance(
        scope_id, fence_sequence, operation_id, authority_revision,
        effect_id, effect_version, authority_id
    ) VALUES (
        p_scope, v_next, p_operation, p_expected_revision,
        p_effect_id, p_effect_version, p_authority_id
    );

    RETURN v_next;
END;
$$;

-- NARF_STATEMENT
CREATE OR REPLACE FUNCTION public.narf_advance_fence_revision(
    p_scope text,
    p_expected_revision bigint,
    p_new_revision bigint
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_revision bigint;
BEGIN
    IF p_scope IS NULL OR p_expected_revision IS NULL OR p_new_revision IS NULL
       OR p_expected_revision < 0 OR p_new_revision <= p_expected_revision THEN
        RAISE EXCEPTION 'narf: invalid authority transition' USING ERRCODE = 'P0001';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_scope, 0));

    SELECT authority_revision INTO v_revision
    FROM public.narf_fence_scopes
    WHERE scope_id = p_scope
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'narf: unknown scope' USING ERRCODE = 'P0001';
    END IF;
    IF v_revision <> p_expected_revision THEN
        RAISE EXCEPTION 'narf: authority revision changed' USING ERRCODE = 'P0001';
    END IF;

    UPDATE public.narf_fence_scopes
    SET authority_revision = p_new_revision
    WHERE scope_id = p_scope;
    RETURN p_new_revision;
END;
$$;

-- NARF_STATEMENT
CREATE OR REPLACE FUNCTION public.narf_commit_fenced_effect(
    p_scope text,
    p_operation uuid,
    p_authority_revision bigint,
    p_fence_sequence bigint,
    p_effect_id text,
    p_effect_version text,
    p_authority_id text,
    p_payload text
)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE
    v_revision bigint;
    v_sequence bigint;
    v_inserted uuid;
BEGIN
    IF p_scope IS NULL OR p_operation IS NULL OR p_authority_revision IS NULL
       OR p_fence_sequence IS NULL OR p_effect_id IS NULL OR p_effect_version IS NULL
       OR p_authority_id IS NULL OR p_payload IS NULL THEN
        RAISE EXCEPTION 'narf: invalid commit request' USING ERRCODE = 'P0001';
    END IF;

    PERFORM pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(p_scope, 0));

    SELECT authority_revision, fence_sequence
    INTO v_revision, v_sequence
    FROM public.narf_fence_scopes
    WHERE scope_id = p_scope;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'narf: unknown scope' USING ERRCODE = 'P0001';
    END IF;
    IF v_revision <> p_authority_revision THEN
        RAISE EXCEPTION 'narf: stale authority revision' USING ERRCODE = 'P0001';
    END IF;
    IF v_sequence <> p_fence_sequence THEN
        RAISE EXCEPTION 'narf: stale fence sequence' USING ERRCODE = 'P0001';
    END IF;

    PERFORM 1
    FROM public.narf_fence_issuance
    WHERE scope_id = p_scope
      AND fence_sequence = p_fence_sequence
      AND operation_id = p_operation
      AND authority_revision = p_authority_revision
      AND effect_id = p_effect_id
      AND effect_version = p_effect_version
      AND authority_id = p_authority_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'narf: issuance evidence mismatch' USING ERRCODE = 'P0001';
    END IF;

    INSERT INTO public.narf_fenced_effects(
        operation_id, scope_id, fence_sequence, authority_revision,
        effect_id, effect_version, payload
    ) VALUES (
        p_operation, p_scope, p_fence_sequence, p_authority_revision,
        p_effect_id, p_effect_version, p_payload
    )
    ON CONFLICT (operation_id) DO NOTHING
    RETURNING operation_id INTO v_inserted;

    IF v_inserted IS NULL THEN
        RAISE EXCEPTION 'narf: operation already committed' USING ERRCODE = 'P0001';
    END IF;
    RETURN v_inserted;
END;
$$;

-- NARF_STATEMENT
REVOKE ALL ON FUNCTION public.narf_current_fence_revision(text) FROM PUBLIC;

-- NARF_STATEMENT
REVOKE ALL ON FUNCTION public.narf_acquire_fence(text, uuid, bigint, text, text, text) FROM PUBLIC;

-- NARF_STATEMENT
REVOKE ALL ON FUNCTION public.narf_advance_fence_revision(text, bigint, bigint) FROM PUBLIC;

-- NARF_STATEMENT
REVOKE ALL ON FUNCTION public.narf_commit_fenced_effect(text, uuid, bigint, bigint, text, text, text, text) FROM PUBLIC;
