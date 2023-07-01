create table if not exists public.deployment
(
    name      text not null,
    uid       text not null
        constraint "Deployment_pk"
            primary key,
    namespace text,
    image     text,
    replicas  integer
);

alter table public.deployment
    owner to alazuser;

create table if not exists public.service
(
    uid        text not null
        constraint "Service_pk"
            primary key,
    name       text,
    namespace  text,
    type       text,
    cluster_ip text,
    deleted    boolean
);

alter table public.service
    owner to alazuser;

create table if not exists public.endpoints
(
    uid       text not null
        constraint "Endpoints_pk"
            primary key,
    name      text,
    namespace text
);

alter table public.endpoints
    owner to alazuser;

create table if not exists public.endpoint_target
(
    ip           text,
    node_name    text,
    kind         text,
    name         text,
    namespace    text,
    endpoint_uid text
        constraint "EndpointTarget_Endpoints_uid_fk"
            references public.endpoints
);

alter table public.endpoint_target
    owner to alazuser;

create table if not exists public.pod
(
    uid             text not null
        constraint "Pod_pk"
            primary key,
    name            text,
    namespace       text,
    image           text,
    "deploymentUid" text,
    ip              text,
    deleted         boolean
);

alter table public.pod
    owner to alazuser;

create table if not exists public.request
(
    start_time  numeric,
    pk          integer generated always as identity
        constraint request_pk
            primary key,
    latency     bigint,
    from_ip     text,
    from_type   text,
    from_uid    text,
    to_ip       text,
    to_type     text,
    to_uid      text,
    protocol    text,
    completed   boolean,
    status_code integer,
    fail_reason text,
    method      text,
    path        text
);

alter table public.request
    owner to alazuser;

