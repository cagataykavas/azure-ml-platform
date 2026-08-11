# Azure ML Platform

A reference architecture for deploying the same ML workload on Microsoft Azure.

```mermaid
flowchart LR
    U[Client] --> FD[Azure Front Door / App Gateway]
    FD --> API[API Management]
    API --> APP[Container Apps / AKS]
    APP --> REDIS[(Azure Cache for Redis)]
    APP --> PG[(Azure Database for PostgreSQL)]
    APP --> BLOB[(Blob Storage)]
    BLOB --> AML[Azure Machine Learning]
    EH[Event Hubs] --> FUNC[Functions / Stream Processing]
    FUNC --> PG
    APP --> MON[Azure Monitor + Application Insights]
    SEC[Key Vault] --> APP
```

## Core services demonstrated

- VNet networking, subnets, NSGs and private endpoints
- Container Apps / AKS for model serving
- Blob Storage for model/data artifacts
- Event Hubs and Service Bus for asynchronous/event-driven workloads
- Azure Database for PostgreSQL and Cosmos DB tradeoffs
- Azure Cache for Redis
- Azure Machine Learning for training, registry and endpoints
- Key Vault, managed identities, Azure Monitor and Application Insights

The same workload is mirrored across clouds to make vendor mapping and architectural tradeoffs explicit.
