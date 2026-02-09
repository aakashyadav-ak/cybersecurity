Network scanning is the process of identifying active hosts, open ports, and services running on a network. It is the second phase of hacking after footprinting.

## Scanning Process Flow
```
┌─────────────────────────────────────────────────────────────────┐
│                    SCANNING PROCESS                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐  │
│   │   HOST   │───▶│   PORT   │───▶│ SERVICE  │───▶│    OS    │  │
│   │DISCOVERY │    │SCANNING  │    │ VERSION  │    │DETECTION │  │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘  │
│                                                                  │
│   Find live       Find open      Identify        Identify       │
│   hosts           ports          services        operating      │
│                                                  system         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```



