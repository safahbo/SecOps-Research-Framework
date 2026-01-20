# SecOps Research Framework (SRF) - Kullanım Kılavuzu

Bu belge, SRF otomasyon aracının kurulum ve kullanım adımlarını içerir.

## 1. Kurulum (Installation)

Framework herhangi bir derleme (compile) işlemi gerektirmez. Doğrudan Bash script olarak çalışır.

### Ön Gereksinimler (Prerequisites)
Sistemin düzgün çalışması için Ubuntu üzerinde aşağıdaki paketlerin yüklü olması gerekir:

```bash
sudo apt update
sudo apt install curl jq wazuh-agent
