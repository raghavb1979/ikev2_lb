# IKEv2 Load Balancer — Flows & Diagrams

Simple views for architecture review, Webex recording, and submission.

---

## 1. Hub–spoke topology (one picture)

```mermaid
flowchart TB
    subgraph spokes["Spoke routers"]
        S1["StrongSwan spoke 1"]
        S2["StrongSwan spoke 2"]
        SN["StrongSwan spoke N"]
    end

    VIP["Hub VIP\nike-lb :500 / :4500"]

    subgraph hub["Hub routers"]
        B1["iked backend 1\nopeniked"]
        B2["iked backend 2\nopeniked"]
        B3["iked backend M\nopeniked"]
    end

    S1 -->|"IKE always to VIP"| VIP
    S2 --> VIP
    SN --> VIP

    VIP -->|"new SA: hash(init SPI)"| B1
    VIP --> B2
    VIP --> B3

    B1 -.->|"IPsec / routing"| DATA["Hub data network"]
    B2 -.-> DATA
    B3 -.-> DATA
```

**In one sentence:** Spokes talk only to the **VIP**; `ike-lb` picks a backend and **sticks** to it for that IKE session.

---

## 2. IKE_SA_INIT flow (first contact)

### Sequence (lab / production initiator path)

```mermaid
sequenceDiagram
    participant Spoke as Spoke StrongSwan
    participant LB as ike-lb VIP
    participant BE as iked backend

    Spoke->>LB: IKE_SA_INIT request Initiator SPI only
    Note over LB: Parse IKE header Responder SPI = 0
    Note over LB: backend = hash Init SPI mod N
    Note over LB: Save session table entry
    LB->>BE: Forward same UDP payload

    BE->>Spoke: IKE_SA_INIT response Responder SPI set
    Note over Spoke: Learns both SPIs

    opt Lab relay mode
        BE->>LB: Response to LB socket
        LB->>Spoke: Relay response
    end

    opt Production asymmetric path
        Note over BE,Spoke: Response may go direct backend to spoke
    end
```

### Steps (numbered)

| Step | Who | What happens |
|------|-----|----------------|
| 1 | Spoke | Sends **IKE_SA_INIT** to **hub VIP** (not backend IP). |
| 2 | `ike-lb` | Reads **Initiator SPI** (first 8 bytes). Responder SPI is zero. |
| 3 | `ike-lb` | Chooses backend: `hash(init_spi) % number_of_backends`. |
| 4 | `ike-lb` | Stores mapping: client address + SPIs → backend index. |
| 5 | `ike-lb` | Forwards UDP datagram to that **iked** (unchanged payload). |
| 6 | `iked` | Builds IKE response (SA, KE, Nonce); sends to spoke. |
| 7 | Spoke | Continues IKE to **VIP** for all later messages (IKE_AUTH, …). |

---

## 3. Existing session (sticky path)

```mermaid
flowchart LR
    A["UDP packet arrives at VIP"] --> B{"Parse IKE header"}
    B --> C{"Session in table?\nclient + Init SPI + Resp SPI"}
    C -->|Yes| D["Use stored backend index"]
    C -->|No new SA only| E["hash Init SPI pick backend"]
    D --> F["Forward to backend UDP"]
    E --> G["Insert session then forward"]
    G --> F
```

| Step | What happens |
|------|----------------|
| 1 | Every IKE packet to VIP includes **both SPIs** (after SA_INIT). |
| 2 | `ike-lb` **looks up** session table → same backend as before. |
| 3 | Packet is **forwarded** to that `iked` only. |
| 4 | **Wrong backend** would break IKE_AUTH / CHILD_SA → stickiness is mandatory. |

---

## 4. Full IKE lifecycle (hub–spoke)

```mermaid
flowchart TD
    start([Spoke needs VPN]) --> sa1[IKE_SA_INIT via VIP]
    sa1 --> lb1[ike-lb selects backend sticky]
    lb1 --> sa1r[Response with Responder SPI]
    sa1r --> auth[IKE_AUTH via VIP same backend]
    auth --> child[CREATE_CHILD_SA ESP tunnel]
    child --> traffic[Encrypted traffic IPsec]
    traffic --> rekey{Rekey or DPD?}
    rekey -->|Still same IKE SA| auth
    rekey -->|New IKE SA| sa1
```

| Phase | Via VIP? | Same backend? |
|-------|----------|---------------|
| IKE_SA_INIT | Yes | Selected here |
| IKE_AUTH | Yes | Must match |
| CREATE_CHILD_SA | Yes | Must match |
| ESP data | No (kernel) | N/A |
| Rekey on same IKE SA | Yes | Must match |

---

## 5. What `ike-lb` does *not* handle

```mermaid
flowchart LR
    LB["ike-lb"] -->|handles| IKE["IKE UDP control plane"]
    ESP["ESP / IPsec data"] -->|handled by| K["kernel + iked / StrongSwan"]
```

- **Does:** UDP 500/4500, SPI stickiness, forward to backends.  
- **Does not:** Terminate IPsec, route spoke LANs, or negotiate certificates (that is **iked** / StrongSwan).

---

## 6. ASCII summary (copy-friendly)

```
  SPOKE                          HUB
  -----                          ---

  [StrongSwan] ----IKE_SA_INIT----> [ VIP : ike-lb ]
                                         |
                                    pick backend
                                         |
                                         v
                                   [ iked hub2 ]
                                         |
  [StrongSwan] <---IKE_SA_INIT resp-----+  (direct or via LB relay)

  [StrongSwan] ----IKE_AUTH--------> [ VIP : ike-lb ] ---> [ iked hub2 ]  (same!)
  [StrongSwan] <=== ESP traffic ===>  hub routing / kernel   (not through LB)
```

---

---

## 7. Lab vs production (practicality)

| Aspect | Lab (`make test`) | Production |
|--------|-------------------|------------|
| Client | `ikev2-client` | StrongSwan spoke |
| Responder | `ikev2-server` × N | openiked × N |
| IKE reply path | **Through LB** (relay) | Often **direct** backend → spoke |
| Initiator IKE | Always to VIP | Always to VIP (required) |
| ESP / routing | Not tested | Kernel + hub routes |

**Test mapping:** [PRACTICALITY.md](PRACTICALITY.md) links each test ID (U/I/P/S) to these flows.

See also: [DESIGN.md](DESIGN.md) (HLD/LLD), [INTEROP.md](INTEROP.md) (StrongSwan / openiked config), [TEST_PLAN.md](TEST_PLAN.md) §2.
