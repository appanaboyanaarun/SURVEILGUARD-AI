# System Architecture & Technical Specifications

## Architectural Overview

The system is designed as a modern decoupled surveillance event intelligence pipeline. Rather than streaming raw high-bandwidth video directly to heavyweight deep neural networks on centralized servers, the system leverages local computer vision edge-processing to extract structured event metadata, and performs machine learning anomaly detection on the structured metadata stream.

```mermaid
flowchart TD
    subgraph VideoIngestion ["1. Video Ingestion & Edge Processing"]
        V[Surveillance Video / CCTV Stream] --> D[OpenCV HOG Person Detector]
        V --> M[MOG2 Background Motion Analyzer]
        D & M --> T[Centroid Multi-Object Tracker]
        T --> Z[Restricted Zone Point-in-Polygon Engine]
    end

    subgraph MetadataGen ["2. Metadata Synthesis"]
        Z --> E[Event Aggregator]
        E -->|Extracts| MD["Event Metadata:
        - camera_id
        - timestamp (HH:MM:SS)
        - location
        - person_count
        - duration (seconds)
        - restricted_area (0/1)
        - motion_level
        - activity_type"]
    end

    subgraph MLArena ["3. Machine Learning Anomaly Detection"]
        MD --> FE[Feature Preprocessing & Standard Scaling]
        FE --> IF[Isolation Forest / One-Class SVM]
        IF --> SC[Score Normalization & Heuristic Calibration]
        SC --> AN{Anomaly Score >= Threshold?}
        AN -->|Yes| SP[Flag SUSPICIOUS + Risk Priority HIGH/MED]
        AN -->|No| NR[Flag NORMAL + Risk Priority LOW]
        SP & NR --> EX[Explainability Engine (Diagnostic Reasons)]
    end

    subgraph StorageOps ["4. Persistence & Security Center"]
        EX --> DB[(SQL Database / SQLite / MySQL)]
        DB --> WS[Alert Dispatcher]
        WS --> UI[Security Operations Dashboard]
        UI --> HR[Human Review & Annotation Studio]
        HR -->|Verification Feedback| DB
    end
```

---

## Technical Innovation & Design Decisions

1. **Automation without Operator Data Entry**:
   - The security guard or operator does **NOT** manually key in camera ID, timestamp, number of persons, duration, or restricted area status.
   - The video-processing pipeline automatically computes these metrics from the video frames.

2. **Computational Efficiency**:
   - The computer vision components (OpenCV HOG Descriptor + MOG2 Background Subtraction + Centroid Tracking) run comfortably at >30 FPS on normal student laptops without requiring CUDA/GPU accelerators.
   - The machine learning anomaly detection executes in sub-milliseconds per event on the extracted feature vectors.

3. **Human-in-the-Loop Verification**:
   - The system is explicitly configured as an **Anomaly & Suspicious Activity Assistant**, not an autonomous judicial crime detector.
   - Flagged incidents are queued for security personnel verification, complete with plain-language reasons and keyframe snapshots.
