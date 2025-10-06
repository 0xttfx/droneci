# Role: drone_secure

Instala e configura o **Drone CI Server** e o **Drone Runner (Docker Runner)** com TLS via Let's Encrypt (modo webroot)  
em **Rocky Linux 9.x com SELinux enforcing**.  

A role é compatível com **NIST SP 800-53 Rev.5**, **PCI-DSS 4.0** e **LGPD Art. 46–49**.

---

## Recursos

- Criação de usuário dedicado (`drone`)
- Configuração segura do SELinux
- Firewall (`firewalld`) com zona isolada
- Certificados Let's Encrypt (modo webroot)
- Deploy dos containers Drone e Runner com SystemD hardening
- Renovação automática de certificados
- Auditoria e logs centralizados (journald)

---

## Exemplo de uso

```yaml
- hosts: drone_hosts
  become: true
  roles:
    - role: drone_secure_role

