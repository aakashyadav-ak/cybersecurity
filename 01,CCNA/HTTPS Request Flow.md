```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                        COMPLETE HTTPS REQUEST JOURNEY                                │
└─────────────────────────────────────────────────────────────────────────────────────┘


 PHASE 1: DNS RESOLUTION
 ════════════════════════════════════════════════════════════════════════════════════

      ┌──────────┐
      │ BROWSER  │
      └────┬─────┘
           │ 1. Check browser DNS cache
           ▼
      ┌──────────┐
      │ OS CACHE │  /etc/hosts, OS DNS cache
      └────┬─────┘
           │ 2. Cache miss
           ▼
      ┌──────────┐
      │  ROUTER  │  Local router DNS cache
      │  CACHE   │
      └────┬─────┘
           │ 3. Cache miss
           ▼
      ┌──────────┐
      │ ISP DNS  │  Recursive resolver (ISP or 8.8.8.8)
      │ RESOLVER │
      └────┬─────┘
           │ 4. Query authoritative DNS
           ▼
      ┌──────────┐
      │ ROUTE 53 │  AWS Authoritative DNS Server
      │          │  Returns: 52.xx.xx.xx (ALB IP)
      └────┬─────┘
           │
           ▼
      IP Address Resolved ✓



 PHASE 2: CONNECTION ESTABLISHMENT
 ════════════════════════════════════════════════════════════════════════════════════

      ┌──────────┐                              ┌──────────┐
      │ BROWSER  │                              │  SERVER  │
      └────┬─────┘                              └────┬─────┘
           │                                         │
           │  ──────── TCP HANDSHAKE ────────       │
           │                                         │
           │  1. SYN ──────────────────────────────▶│
           │                                         │
           │◀────────────────────────────── 2. SYN-ACK
           │                                         │
           │  3. ACK ──────────────────────────────▶│
           │                                         │
           │  ════════ TCP ESTABLISHED ════════     │
           │                                         │
           │  ──────── TLS HANDSHAKE ────────       │
           │                                         │
           │  4. ClientHello ──────────────────────▶│
           │     (Supported ciphers, TLS version)   │
           │                                         │
           │◀────────────────────────── 5. ServerHello
           │     (Selected cipher, certificate)     │
           │                                         │
           │  6. Verify Certificate                 │
           │     (Check CA, expiry, domain)         │
           │                                         │
           │  7. Key Exchange ─────────────────────▶│
           │     (Pre-master secret)                │
           │                                         │
           │◀─────────────────────────── 8. Finished│
           │                                         │
           │  ════════ TLS ESTABLISHED ════════     │
           │  (All further data is encrypted)       │
           │                                         │



 PHASE 3: REQUEST PROCESSING (Your Original Flow - Corrected)
 ════════════════════════════════════════════════════════════════════════════════════

                    ENCRYPTED HTTPS REQUEST
                    ───────────────────────
                    GET /api/users HTTP/2
                    Host: api.example.com
                    Authorization: Bearer <JWT>
                              │
                              ▼
                    ┌─────────────────┐
                    │   CLOUDFRONT    │  CDN Edge Location
                    │      (CDN)      │  ───────────────────
                    │                 │  • Cache static assets
                    │                 │  • Edge computing
                    │                 │  • Compress content
                    └────────┬────────┘
                             │ Cache MISS (dynamic content)
                             ▼
                    ┌─────────────────┐
                    │   AWS SHIELD    │  DDoS Protection
                    │                 │  ───────────────────
                    │                 │  • Layer 3/4 protection
                    │                 │  • Volumetric attacks
                    │                 │  • SYN floods
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │    AWS WAF      │  Web Application Firewall
                    │                 │  ───────────────────────
                    │                 │  • Layer 7 protection
                    │                 │  • SQL injection
                    │                 │  • XSS attacks
                    │                 │  • Rate limiting
                    └────────┬────────┘
                             │
                             ▼
          ┌──────────────────────────────────────────┐
          │              AWS VPC                      │
          │  ┌────────────────────────────────────┐  │
          │  │           NACL (Stateless)         │  │
          │  │  • Subnet-level firewall           │  │
          │  │  • Allow/Deny by IP & Port         │  │
          │  └─────────────────┬──────────────────┘  │
          │                    │                      │
          │                    ▼                      │
          │  ┌────────────────────────────────────┐  │
          │  │        SECURITY GROUP (Stateful)   │  │
          │  │  • Instance-level firewall         │  │
          │  │  • Allow rules only                │  │
          │  └─────────────────┬──────────────────┘  │
          │                    │                      │
          │                    ▼                      │
          │  ┌────────────────────────────────────┐  │
          │  │         LOAD BALANCER              │  │
          │  │  ┌──────────┐    ┌──────────┐      │  │
          │  │  │   NLB    │ OR │   ALB    │      │  │
          │  │  │  (L4)    │    │   (L7)   │      │  │
          │  │  │          │    │          │      │  │
          │  │  │ TCP/UDP  │    │  HTTP    │      │  │
          │  │  │ routing  │    │  routing │      │  │
          │  │  └────┬─────┘    └────┬─────┘      │  │
          │  │       └───────┬───────┘            │  │
          │  └───────────────┼────────────────────┘  │
          │                  │                        │
          │                  ▼                        │
          │  ┌────────────────────────────────────┐  │
          │  │        REVERSE PROXY               │  │
          │  │        (NGINX / Envoy)             │  │
          │  │  ──────────────────────────        │  │
          │  │  • SSL termination (if not at LB)  │  │
          │  │  • Request buffering               │  │
          │  │  • Compression                     │  │
          │  │  • Static file serving             │  │
          │  │  • Connection pooling              │  │
          │  └─────────────────┬──────────────────┘  │
          │                    │                      │
          │                    ▼                      │
          │  ┌────────────────────────────────────┐  │
          │  │          API GATEWAY               │  │
          │  │   (Kong / AWS API GW / Custom)     │  │
          │  │  ──────────────────────────────    │  │
          │  │  • JWT Token Validation            │  │
          │  │     ┌─────────────────────────┐    │  │
          │  │     │ 1. Extract Bearer token │    │  │
          │  │     │ 2. Verify signature     │    │  │
          │  │     │ 3. Check expiration     │    │  │
          │  │     │ 4. Validate claims      │    │  │
          │  │     │ 5. Check permissions    │    │  │
          │  │     └─────────────────────────┘    │  │
          │  │  • Rate limiting (per user/IP)     │  │
          │  │  • Request transformation          │  │
          │  │  • API versioning                  │  │
          │  │  • Request/Response logging        │  │
          │  └─────────────────┬──────────────────┘  │
          │                    │                      │
          └────────────────────┼──────────────────────┘
                               │
                               ▼
          ┌────────────────────────────────────────────────────────────┐
          │                  KUBERNETES CLUSTER                         │
          │  ┌──────────────────────────────────────────────────────┐  │
          │  │              INGRESS CONTROLLER                       │  │
          │  │         (NGINX Ingress / Traefik / Istio)            │  │
          │  └───────────────────────┬──────────────────────────────┘  │
          │                          │                                  │
          │                          ▼                                  │
          │  ┌──────────────────────────────────────────────────────┐  │
          │  │              SERVICE MESH (Optional)                  │  │
          │  │                  (Istio / Linkerd)                    │  │
          │  │  ────────────────────────────────────────────         │  │
          │  │  • mTLS between services                              │  │
          │  │  • Traffic management                                 │  │
          │  │  • Circuit breaking                                   │  │
          │  │  • Retry logic                                        │  │
          │  │  • Distributed tracing                                │  │
          │  └───────────────────────┬──────────────────────────────┘  │
          │                          │                                  │
          │        ┌─────────────────┼─────────────────┐                │
          │        │                 │                 │                │
          │        ▼                 ▼                 ▼                │
          │  ┌───────────┐    ┌───────────┐    ┌───────────┐           │
          │  │   USER    │    │   ORDER   │    │  PAYMENT  │           │
          │  │  SERVICE  │    │  SERVICE  │    │  SERVICE  │           │
          │  │           │    │           │    │           │           │
          │  │ ┌───────┐ │    │ ┌───────┐ │    │ ┌───────┐ │           │
          │  │ │ Pod 1 │ │    │ │ Pod 1 │ │    │ │ Pod 1 │ │           │
          │  │ │ Pod 2 │ │    │ │ Pod 2 │ │    │ │ Pod 2 │ │           │
          │  │ └───────┘ │    │ └───────┘ │    │ └───────┘ │           │
          │  └─────┬─────┘    └─────┬─────┘    └─────┬─────┘           │
          │        │                │                │                  │
          │        └────────────────┼────────────────┘                  │
          │                         │                                   │
          └─────────────────────────┼───────────────────────────────────┘
                                    │
                                    ▼
          ┌────────────────────────────────────────────────────────────┐
          │                      DATA LAYER                             │
          │                                                             │
          │   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
          │   │    RDS      │  │ ELASTICACHE │  │     S3      │        │
          │   │  (Postgres) │  │   (Redis)   │  │   (Files)   │        │
          │   │             │  │             │  │             │        │
          │   │ • Primary   │  │ • Session   │  │ • Static    │        │
          │   │ • Read      │  │ • Cache     │  │ • Uploads   │        │
          │   │   Replicas  │  │ • Pub/Sub   │  │ • Backups   │        │
          │   └─────────────┘  └─────────────┘  └─────────────┘        │
          │                                                             │
          └─────────────────────────────────────────────────────────────┘



 PHASE 4: RESPONSE JOURNEY
 ════════════════════════════════════════════════════════════════════════════════════

          ┌─────────────────────────────────────────────────────────────┐
          │                    RESPONSE PATH                            │
          │                                                             │
          │   Database → Microservice → Service Mesh → K8s Service     │
          │      → Ingress → API Gateway → Reverse Proxy               │
          │      → Load Balancer → Security Groups → NACL              │
          │      → WAF → Shield → CloudFront (cache response)          │
          │      → Internet → Browser                                   │
          │                                                             │
          └─────────────────────────────────────────────────────────────┘

          Response Headers Include:
          ┌─────────────────────────────────────────────────────────────┐
          │  HTTP/2 200 OK                                              │
          │  Content-Type: application/json                             │
          │  X-Request-ID: abc-123-def                                  │
          │  X-Response-Time: 45ms                                      │
          │  Cache-Control: private, max-age=0                          │
          │  Strict-Transport-Security: max-age=31536000               │
          │                                                             │
          │  {"users": [...]}                                           │
          └─────────────────────────────────────────────────────────────┘



 PHASE 5: OBSERVABILITY (Throughout the Request)
 ════════════════════════════════════════════════════════════════════════════════════

     ┌─────────────────────────────────────────────────────────────────────────┐
     │                                                                          │
     │   ┌─────────────┐    ┌─────────────┐    ┌─────────────┐                 │
     │   │   LOGGING   │    │   METRICS   │    │   TRACING   │                 │
     │   │             │    │             │    │             │                 │
     │   │ CloudWatch  │    │ Prometheus  │    │  AWS X-Ray  │                 │
     │   │ ELK Stack   │    │ Grafana     │    │  Jaeger     │                 │
     │   │ Fluentd     │    │ Datadog     │    │  Zipkin     │                 │
     │   │             │    │             │    │             │                 │
     │   │ • Access    │    │ • Latency   │    │ • Request   │                 │
     │   │   logs      │    │ • RPS       │    │   flow      │                 │
     │   │ • Error     │    │ • Error     │    │ • Service   │                 │
     │   │   logs      │    │   rates     │    │   deps      │                 │
     │   │ • Audit     │    │ • CPU/Mem   │    │ • Bottleneck│                 │
     │   │   logs      │    │   usage     │    │   detection │                 │
     │   └─────────────┘    └─────────────┘    └─────────────┘                 │
     │                                                                          │
     └─────────────────────────────────────────────────────────────────────────┘
```