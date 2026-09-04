# [Build a dedicated Threat Intelligence platform and apply AI/ML to enhance detection] Backend Service
> **Lưu ý về kiến trúc:** Mã nguồn Frontend (Dashboard) được quản lý độc lập tại:  
> 👉 [Frontend Dashboard Repository](https://github.com/kikasssss/dashboard)
---

## 🛠 Công nghệ sử dụng
* Backend: Python3, Flask
* Frontend: Next.js, TypeScript, Tailwind CSS
* Thu thập và CSDL: Filebeat, Logtash, Elasticsearch, MongoDB
* Threat Intelligence: ThreatFox, AbuseIPDB
* AL/ML: Catboost, GPT API

## Key Features

- Centralized security log collection
- Security event normalization
- IDS/IPS monitoring using Snort
- SIEM using OpenSearch
- Threat Intelligence enrichment
- IOC collection from ThreatFox and AbuseIPDB
- Automated Snort rule generation
- Attack window construction
- MITRE ATT&CK behavior mapping
- AI-assisted attack correlation
- SOC monitoring dashboard
